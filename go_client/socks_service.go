// SPDX-License-Identifier: GPL-3.0-or-later
// SOCKS5 TCP CONNECT + UDP ASSOCIATE. Both remote protocols use ONLY the
// in-process WireGuard netstack. Host sockets accept clients on loopback.
package main

import (
    "context"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "net"
    "net/netip"
    "strings"
    "sync"
    "time"

    "golang.zx2c4.com/wireguard/tun/netstack"
)

const (
    wdttMaxSOCKSClients = 32
    wdttMaxUDPAssociations = 4
    wdttMaxUDPPayload = 2048
    wdttMaxUDPFrame = 2304
)

type wdttSocksTarget struct {
    host string
    port uint16
    kind byte
}
var errWDTTAddress = errors.New("unsupported SOCKS5 address")

func wdttReadTarget(r io.Reader, kind byte) (wdttSocksTarget, error) {
    target := wdttSocksTarget{kind:kind}
    switch kind {
    case 1:
        var addr [4]byte
        if _, err := io.ReadFull(r, addr[:]); err != nil { return target, err }
        target.host = net.IP(addr[:]).String()
    case 3:
        var length [1]byte
        if _, err := io.ReadFull(r, length[:]); err != nil { return target, err }
        if length[0] == 0 || length[0] > 253 { return target, errWDTTAddress }
        data := make([]byte, int(length[0]))
        if _, err := io.ReadFull(r, data); err != nil { return target, err }
        for _, b := range data {
            if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
                b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_') {
                return target, errWDTTAddress
            }
        }
        target.host = string(data)
    default:
        return target, errWDTTAddress // IPv6 never sent directly or tunneled
    }
    var pb [2]byte
    if _, err := io.ReadFull(r, pb[:]); err != nil { return target, err }
    target.port = binary.BigEndian.Uint16(pb[:])
    return target, nil
}

func wdttSocksReply(c net.Conn, status byte, ip net.IP, port int) error {
    if ip == nil { ip = net.IPv4zero }
    addr := ip.To4()
    if addr == nil { addr = net.IPv4zero.To4() }
    var result [10]byte
    result[0],result[1],result[2],result[3] = 5,status,0,1
    copy(result[4:8],addr)
    binary.BigEndian.PutUint16(result[8:10],uint16(port))
    _, err := c.Write(result[:])
    return err
}

func wdttResolveIPv4(ctx context.Context, tnet *netstack.Net, target wdttSocksTarget) (*net.UDPAddr,error) {
    if target.port == 0 { return nil,errWDTTAddress }
    if target.kind == 1 {
        ip := net.ParseIP(target.host).To4()
        if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || ip.IsLoopback() {
            return nil,errWDTTAddress
        }
        return &net.UDPAddr{IP:ip,Port:int(target.port)},nil
    }
    addresses,err := tnet.LookupContextHost(ctx,target.host)
    if err != nil { return nil,err }
    for _, s := range addresses {
        ip := net.ParseIP(s).To4()
        if ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && !ip.Equal(net.IPv4bcast) {
            return &net.UDPAddr{IP:ip,Port:int(target.port)},nil
        }
    }
    return nil,errWDTTAddress
}

func wdttSocksHandshake(c net.Conn) (byte,wdttSocksTarget,error) {
    var h [2]byte
    if _,err := io.ReadFull(c,h[:]); err != nil { return 0,wdttSocksTarget{},err }
    if h[0] != 5 || h[1] == 0 || h[1] > 16 { return 0,wdttSocksTarget{},errors.New("SOCKS negotiation rejected") }
    methods:=make([]byte,h[1])
    if _,err := io.ReadFull(c,methods); err != nil { return 0,wdttSocksTarget{},err }
    accepted:=false
    for _,m:=range methods { if m==0 { accepted=true; break } }
    if !accepted {
        _,_ = c.Write([]byte{5,255})
        return 0,wdttSocksTarget{},errors.New("SOCKS no supported authentication")
    }
    if _,err := c.Write([]byte{5,0}); err != nil { return 0,wdttSocksTarget{},err }
    var req [4]byte
    if _,err := io.ReadFull(c,req[:]); err != nil { return 0,wdttSocksTarget{},err }
    if req[0]!=5 || req[2]!=0 { return 0,wdttSocksTarget{},errors.New("SOCKS request rejected") }
    target,err:=wdttReadTarget(c,req[3])
    if err != nil {
        _=wdttSocksReply(c,8,nil,0)
        return 0,wdttSocksTarget{},err
    }
    return req[1],target,nil
}

func wdttTCPConnect(ctx context.Context, c net.Conn, tnet *netstack.Net, target wdttSocksTarget) {
    dialCtx,cancel:=context.WithTimeout(ctx,10*time.Second)
    addr,err:=wdttResolveIPv4(dialCtx,tnet,target)
    if err!=nil {
        cancel()
        _=wdttSocksReply(c,4,nil,0)
        return
    }
    remote,err:=tnet.DialContext(dialCtx,"tcp",addr.String())
    cancel()
    if err!=nil {
        _=wdttSocksReply(c,4,nil,0)
        return
    }
    defer remote.Close()
    if wdttSocksReply(c,0,nil,0)!=nil { return }
    _=c.SetDeadline(time.Now().Add(3*time.Minute))
    done:=make(chan struct{},2)
    transfer:=func(dst net.Conn,src net.Conn){
        _,_=io.CopyBuffer(dst,src,make([]byte,16*1024))
        if cw,ok:=dst.(interface{CloseWrite() error});ok { _=cw.CloseWrite() }else{ _=dst.Close() }
        done<-struct{}{}
    }
    go transfer(remote,c)
    go transfer(c,remote)
    <-done
    <-done
}

// Serve only literal loopback; both existing SOCKS status codes and the
// original private owner-only config admission remain in force.
func runSocks5Server(ctx context.Context, listenAddr string, tnet *netstack.Net) error {
    if listenAddr!="127.0.0.1:1081" { return errors.New("SOCKS loopback only") }
    ln,err:=net.Listen("tcp4",listenAddr)
    if err!=nil {
        labSocksStatus("SOCKS_BIND_FAILED")
        return fmt.Errorf("SOCKS loopback bind: %w",err)
    }
    defer ln.Close()
    labSocksStatus("SOCKS_LISTENING")
    closeOnCancel:=context.AfterFunc(ctx,func(){ _=ln.Close() })
    defer closeOnCancel()

    clients:=make(chan struct{},wdttMaxSOCKSClients)
    udpSessions:=make(chan struct{},wdttMaxUDPAssociations)
    var wg sync.WaitGroup
    defer wg.Wait()
    for {
        c,acceptErr:=ln.Accept()
        if acceptErr!=nil {
            if ctx.Err()!=nil { return nil }
            return acceptErr
        }
        select {
        case clients<-struct{}{}:
        default:
            _=c.Close()
            continue
        }
        wg.Add(1)
        go func(){
            defer wg.Done()
            defer func(){<-clients}()
            defer c.Close()
            stop:=context.AfterFunc(ctx,func(){_ = c.Close()})
            defer stop()
            _=c.SetDeadline(time.Now().Add(10*time.Second))
            command,target,err:=wdttSocksHandshake(c)
            if err!=nil { return }
            _=c.SetDeadline(time.Time{})
            switch command {
            case 1:
                wdttTCPConnect(ctx,c,tnet,target)
            case 3:
                select {
                case udpSessions<-struct{}{}:
                    defer func(){<-udpSessions}()
                    wdttUDPAssociate(ctx,c,tnet,target)
                default:
                    _=wdttSocksReply(c,1,nil,0)
                }
            default:
                _=wdttSocksReply(c,7,nil,0)
            }
        }()
    }
}

// Return the client IPv4 address for association pinning (never internet-facing).
func wdttClientIP(c net.Conn) net.IP {
    ta,ok:=c.RemoteAddr().(*net.TCPAddr)
    if !ok{return nil}
    ip:=ta.IP.To4()
    if ip==nil || !ip.IsLoopback(){return nil}
    return ip
}

func wdttIsUDPAssociateSource(target wdttSocksTarget, caller net.IP) bool {
    if target.kind!=1{return false}
    ip:=net.ParseIP(target.host).To4()
    if ip==nil{return false}
    return ip.IsUnspecified() || ip.Equal(caller)
}

func wdttPacketAddr(ip net.IP,port uint16) string {
    return netip.AddrPortFrom(netip.MustParseAddr(ip.To4().String()),port).String()
}

func wdttPrivateDomain(domain string) bool {
    return domain!="" && !strings.ContainsAny(domain," \x00\r\n\t")
}
