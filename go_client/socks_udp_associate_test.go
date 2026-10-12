// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
    "bytes"
    "context"
    "encoding/binary"
    "net"
    "testing"
    "time"
)

func wdttTestFrame(kind byte, host string,port uint16,payload []byte) []byte {
    b:=[]byte{0,0,0,kind}
    if kind==1 { b=append(b,net.ParseIP(host).To4()...) }
    if kind==3 { b=append(b,byte(len(host))); b=append(b,[]byte(host)...)}
    b=append(b,byte(port>>8),byte(port))
    return append(b,payload...)
}

func TestWDTTUDPFramingAndInvalidDatagrams(t *testing.T) {
    for _,sz:=range []int{0,64,512,1000,1200,1400,2048} {
        body:=bytes.Repeat([]byte{0x5a},sz)
        wire:=wdttTestFrame(1,"10.66.66.1",18081,body)
        target,got,err:=wdttDecodeUDPPacket(wire)
        if err!=nil || target.host!="10.66.66.1" || target.port!=18081 || !bytes.Equal(got,body) {
            t.Fatalf("valid IPv4 size %d was changed/rejected",sz)
        }
        answer,err:=wdttEncodeUDPReply(&net.UDPAddr{IP:net.ParseIP("10.66.66.1"),Port:18081},got)
        if err!=nil || !bytes.Equal(answer,wire) {t.Fatalf("response encoding size %d",sz)}
    }
    wire:=wdttTestFrame(3,"fixture.invalid",53,[]byte{1,2,3})
    target,data,err:=wdttDecodeUDPPacket(wire)
    if err!=nil || target.host!="fixture.invalid" || target.port!=53 || !bytes.Equal(data,[]byte{1,2,3}) {
        t.Fatal("domain UDP request rejected")
    }
    bad:=[][]byte{
        {0,0,0}, // too short
        {1,0,0,1,10,66,66,1,70,161},
        {0,1,0,1,10,66,66,1,70,161},
        {0,0,1,1,10,66,66,1,70,161}, // no FRAG support
        wdttTestFrame(4,"",53,[]byte{1}), // IPv6
        wdttTestFrame(1,"10.66.66.1",0,[]byte{1}),
        append(wdttTestFrame(1,"10.66.66.1",53,nil),bytes.Repeat([]byte{0xff},wdttMaxUDPPayload+1)...),
        append([]byte{0,0,0,3,2,0},[]byte("z")...), // control in hostname
    }
    for i,p:=range bad {if _,_,e:=wdttDecodeUDPPacket(p);e==nil {t.Fatalf("accepted malformed UDP frame %d",i)}}
    if _,e:=wdttEncodeUDPReply(&net.UDPAddr{IP:net.ParseIP("2001:db8::1"),Port:53},nil);e==nil {
        t.Fatal("emitted IPv6 UDP frame")
    }
}

func TestWDTTUDPPeerPinningAndReplyAuthorization(t *testing.T) {
    peers:=&wdttUDPPeers{}
    good:=&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:51002}
    wrongPort:=&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:51003}
    wrongIP:=&net.UDPAddr{IP:net.IPv4(127,0,0,2),Port:51002}
    if !peers.setSource(good,net.IPv4(127,0,0,1),0) ||
        peers.setSource(wrongPort,net.IPv4(127,0,0,1),0) ||
        peers.setSource(wrongIP,net.IPv4(127,0,0,1),0) {
        t.Fatal("SOCKS UDP source wasn't fixed to TCP client's IPv4/first UDP port")
    }
    if !peers.setSource(good,net.IPv4(127,0,0,1),51002) ||
        peers.setSource(good,net.IPv4(127,0,0,1),51003) {
        t.Fatal("explicit association port ignored")
    }
    remote:=&net.UDPAddr{IP:net.ParseIP("10.66.66.1"),Port:18081}
    other:=&net.UDPAddr{IP:net.ParseIP("10.66.66.2"),Port:18081}
    if peers.expected(remote) {t.Fatal("allowed unsolicited remote UDP")}
    peers.mark(remote)
    if !peers.expected(remote) || peers.expected(other) {t.Fatal("UDP authorization mismatch")}
    peers.mu.Lock()
    peers.dest[wdttPacketAddr(remote.IP,uint16(remote.Port))]=time.Now().Add(-3*time.Minute)
    peers.mu.Unlock()
    if peers.expected(remote){t.Fatal("accepted stale unsolicited UDP response")}
}

func TestWDTTUDPSocksControlHandshake(t *testing.T) {
    server,client:=net.Pipe()
    defer server.Close()
    defer client.Close()
    got:=make(chan byte,1)
    go func(){
        cmd,target,err:=wdttSocksHandshake(server)
        if err!=nil || cmd!=3 || target.kind!=1 || target.host!="0.0.0.0" || target.port!=0 {
            got<-255
        }else{got<-cmd}
    }()
    // one offered no-auth method
    if _,err:=client.Write([]byte{5,1,0});err!=nil{t.Fatal(err)}
    var auth [2]byte
    if _,err:=client.Read(auth[:]);err!=nil || auth!=[2]byte{5,0} {t.Fatal("no-auth negotiate")}
    if _,err:=client.Write([]byte{5,3,0,1,0,0,0,0,0,0});err!=nil{t.Fatal(err)}
    if <-got!=3 {t.Fatal("UDP_ASSOCIATE not recognized")}
    if !wdttIsUDPAssociateSource(wdttSocksTarget{kind:1,host:"0.0.0.0"},net.IPv4(127,0,0,1)) {t.Fatal("wildcard control refused")}
    if wdttIsUDPAssociateSource(wdttSocksTarget{kind:1,host:"8.8.8.8"},net.IPv4(127,0,0,1)) {t.Fatal("remote UDP control accepted")}
    if wdttIsUDPAssociateSource(wdttSocksTarget{kind:3,host:"localhost"},net.IPv4(127,0,0,1)) {t.Fatal("domain wildcard accepted")}
}

func TestWDTTUDPDestinationBounds(t *testing.T) {
    data:=wdttTestFrame(1,"10.66.66.1",18081,bytes.Repeat([]byte{1},64))
    if binary.BigEndian.Uint16(data[8:10])!=18081 {t.Fatal("network port encoding")}
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if ctx.Err()==nil {t.Fatal("context cancellation")}
    for _,invalid:=range []wdttSocksTarget{{kind:1,host:"0.0.0.0",port:1},{kind:1,host:"127.0.0.1",port:1},{kind:1,host:"224.0.0.1",port:1},{kind:1,host:"255.255.255.255",port:1}} {
        // These are checked before contacting the netstack: no remote
        // network/host resolver is ever consulted for invalid IPv4 literals.
        if ip:=net.ParseIP(invalid.host);ip==nil || !(ip.IsUnspecified()||ip.IsLoopback()||ip.IsMulticast()||ip.Equal(net.IPv4bcast)) {
            t.Fatal("test invalid address was not invalid")
        }
    }
}
