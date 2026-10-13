// SPDX-License-Identifier: GPL-3.0-or-later
// SOCKS5 UDP ASSOCIATE RFC1928 framing, with no direct-Internet fallback.
package main

import (
    "bytes"
    "context"
    "encoding/binary"
    "errors"
    "net"
    "sync"
    "sync/atomic"
    "time"

    "golang.zx2c4.com/wireguard/tun/netstack"
)

var errWDTTUDPFrame = errors.New("invalid or fragmented SOCKS UDP frame")

func wdttDecodeUDPPacket(packet []byte) (wdttSocksTarget, []byte, error) {
    if len(packet)<10 || len(packet)>wdttMaxUDPFrame ||
        packet[0]!=0 || packet[1]!=0 || packet[2]!=0 {
        return wdttSocksTarget{},nil,errWDTTUDPFrame
    }
    reader:=bytes.NewReader(packet[4:])
    target,err:=wdttReadTarget(reader,packet[3])
    if err!=nil || target.port==0 { return wdttSocksTarget{},nil,errWDTTUDPFrame }
    payload:=packet[len(packet)-reader.Len():]
    if len(payload)>wdttMaxUDPPayload { return wdttSocksTarget{},nil,errWDTTUDPFrame }
    return target,payload,nil
}

func wdttEncodeUDPReply(addr *net.UDPAddr, payload []byte) ([]byte,error) {
    return wdttEncodeUDPReplyInto(nil,addr,payload)
}

// Session-private scratch; WriteToUDP consumes it synchronously.
func wdttEncodeUDPReplyInto(dst []byte,addr *net.UDPAddr, payload []byte) ([]byte,error) {
    if addr==nil || addr.Port<=0 || addr.Port>65535 || len(payload)>wdttMaxUDPPayload {
        return nil,errWDTTUDPFrame
    }
    ip:=addr.IP.To4()
    if ip==nil { return nil,errWDTTUDPFrame }
    size:=10+len(payload)
    var packet []byte
    if cap(dst)>=size {packet=dst[:size]} else {packet=make([]byte,size)}
    clear(packet[:10])
    packet[3]=1
    copy(packet[4:8],ip)
    binary.BigEndian.PutUint16(packet[8:10],uint16(addr.Port))
    copy(packet[10:],payload)
    return packet,nil
}

type wdttUDPPeers struct {
    mu sync.Mutex
    dest map[string]time.Time
    src *net.UDPAddr
}

func (p *wdttUDPPeers) setSource(addr *net.UDPAddr,expected net.IP,port uint16) bool {
    if addr==nil || !addr.IP.Equal(expected) || port!=0 && uint16(addr.Port)!=port {
        return false
    }
    p.mu.Lock()
    defer p.mu.Unlock()
    if p.src==nil {
        p.src=&net.UDPAddr{IP:append(net.IP(nil),addr.IP...),Port:addr.Port}
    }
    return addr.Port==p.src.Port
}
func (p *wdttUDPPeers) source() *net.UDPAddr {
    p.mu.Lock()
    defer p.mu.Unlock()
    if p.src==nil {return nil}
    return &net.UDPAddr{IP:append(net.IP(nil),p.src.IP...),Port:p.src.Port}
}
func (p *wdttUDPPeers) mark(addr *net.UDPAddr) {
    p.mu.Lock()
    defer p.mu.Unlock()
    if p.dest==nil { p.dest=make(map[string]time.Time) }
    now:=time.Now()
    for k,t:=range p.dest { if now.Sub(t)>2*time.Minute {delete(p.dest,k)} }
    if len(p.dest)>=32 {
        var oldest string
        var when time.Time
        for k,t:=range p.dest {if when.IsZero() || t.Before(when){when,oldest=t,k}}
        delete(p.dest,oldest)
    }
    p.dest[wdttPacketAddr(addr.IP,uint16(addr.Port))]=now
}
func (p *wdttUDPPeers) expected(addr *net.UDPAddr) bool {
    if addr==nil || addr.IP.To4()==nil || addr.Port<=0 || addr.Port>65535{return false}
    p.mu.Lock()
    defer p.mu.Unlock()
    at,ok:=p.dest[wdttPacketAddr(addr.IP,uint16(addr.Port))]
    return ok && time.Since(at)<=2*time.Minute
}

func wdttUDPAssociate(ctx context.Context, control net.Conn, tnet *netstack.Net, request wdttSocksTarget) {
    caller:=wdttClientIP(control)
    if caller==nil || !wdttIsUDPAssociateSource(request,caller) {
        wdttTelemetry.udpAssocFailed.Add(1)
        _=wdttSocksReply(control,2,nil,0)
        return
    }
    inbound,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:0})
    if err!=nil {
        wdttTelemetry.udpAssocFailed.Add(1)
        _=wdttSocksReply(control,1,nil,0)
        return
    }
    defer inbound.Close()

    // The outbound UDP socket belongs to the WireGuard userspace network,
    // not to the host kernel; there is deliberately no net.DialUDP fallback.
    outbound,err:=tnet.ListenUDP(&net.UDPAddr{IP:net.IPv4zero,Port:0})
    if err!=nil {
        wdttTelemetry.udpAssocFailed.Add(1)
        _=wdttSocksReply(control,1,nil,0)
        return
    }
    defer outbound.Close()

    binding:=inbound.LocalAddr().(*net.UDPAddr)
    if wdttSocksReply(control,0,net.IPv4(127,0,0,1),binding.Port)!=nil { wdttTelemetry.udpAssocFailed.Add(1); return }
    wdttTelemetry.udpAssocReady.Add(1)
    started:=time.Now()
    var clientPackets atomic.Uint64
    defer func(){
        wdttLife.udpCompleted.Add(1)
        wdttLifeDuration(false,time.Since(started))
        if clientPackets.Load()==0 {wdttLife.udpNoClientData.Add(1)}
    }()
    active:=wdttTelemetry.udpAssocActive.Add(1)
    wdttTelemetryPeak(&wdttTelemetry.udpAssocPeak,active)
    defer wdttTelemetry.udpAssocActive.Add(-1)
    labUDPStatus("UDP_ASSOCIATE_READY")

    closed:=make(chan struct{})
    var endedByControl atomic.Bool
    go func(){
        defer close(closed)
        var one [1]byte
        for {
            if _,err:=control.Read(one[:]);err!=nil {
                wdttLifeUDPControlEnd(err)
                break
            }
        }
        endedByControl.Store(true)
        _=inbound.Close()
        _=outbound.Close()
    }()

    peers:=&wdttUDPPeers{}
    var receivers sync.WaitGroup
    receivers.Add(1)
    go func(){
        defer receivers.Done()
        buf:=make([]byte,wdttMaxUDPPayload+1)
        var replyBuf []byte
        for {
            n,src,err:=outbound.ReadFrom(buf)
            if err!=nil {return}
            remote,ok:=src.(*net.UDPAddr)
            if !ok || n>wdttMaxUDPPayload || !peers.expected(remote){wdttTelemetry.udpRepliesRejected.Add(1);continue}
            target:=peers.source()
            if target==nil{wdttTelemetry.udpRepliesRejected.Add(1);continue}
            wrapped,err:=wdttEncodeUDPReplyInto(replyBuf,remote,buf[:n])
            if err!=nil {wdttTelemetry.udpRepliesRejected.Add(1);continue}
            replyBuf=wrapped
            if _,err=inbound.WriteToUDP(wrapped,target);err!=nil {wdttTelemetry.udpHostWriteFailed.Add(1)} else {
                wdttTelemetry.udpRepliesDelivered.Add(1)
                wdttTelemetry.udpReplyBytes.Add(uint64(n))
            }
        }
    }()
    defer func(){
        _=inbound.Close()
        _=outbound.Close()
        receivers.Wait()
    }()

    buf:=make([]byte,wdttMaxUDPFrame+1)
    for ctx.Err()==nil {
        _=inbound.SetReadDeadline(time.Now().Add(time.Second))
        n,src,err:=inbound.ReadFromUDP(buf)
        if err!=nil {
            if ctx.Err()!=nil {break}
            if te,ok:=err.(net.Error);ok && te.Timeout(){continue}
            if endedByControl.Load(){
                wdttLife.udpHostReadAfterControlClose.Add(1)
            } else {
                wdttTelemetry.udpHostReadFailed.Add(1)
                wdttLife.udpHostReadUnexpected.Add(1)
            }
            break
        }
        if n>wdttMaxUDPFrame || !peers.setSource(src,caller,request.port) {wdttTelemetry.udpClientSourceRejected.Add(1);continue}
        target,data,err:=wdttDecodeUDPPacket(buf[:n])
        if err!=nil {wdttTelemetry.udpClientMalformed.Add(1);continue}
        wdttTelemetry.udpClientValid.Add(1)
        clientPackets.Add(1)
        wdttTelemetry.udpClientBytes.Add(uint64(len(data)))
        lookupCtx,cancel:=context.WithTimeout(ctx,4*time.Second)
        addr,err:=wdttResolveIPv4(lookupCtx,tnet,target)
        cancel()
        if err!=nil {wdttTelemetry.udpResolveFailed.Add(1);continue}
        peers.mark(addr)
        if _,err=outbound.WriteTo(data,addr);err!=nil {wdttTelemetry.udpWGWriteFailed.Add(1)} else {wdttTelemetry.udpToWG.Add(1)}
    }
    // The control connection owns the association; close both packet sockets
    // when it disappears even if the process continues serving TCP.
    select {case <-closed: default:}
}
