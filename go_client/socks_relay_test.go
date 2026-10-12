// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
    "context"
    "io"
    "net"
    "testing"
    "time"
)

func wdttAwaitRelay(t *testing.T, done <-chan struct{}, limit time.Duration) {
    t.Helper()
    select {
    case <-done:
    case <-time.After(limit):
        t.Fatal("SOCKS TCP relay stranded copy goroutines / slot")
    }
}

func TestWDTTRelayCancelClosesBothBlockedDirections(t *testing.T) {
    client, clientPeer := net.Pipe()
    remote, remotePeer := net.Pipe()
    defer clientPeer.Close()
    defer remotePeer.Close()
    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan struct{})
    go func() {wdttRelayTCP(ctx, client, remote, time.Minute);close(done)}()
    cancel() // both copies were blocked in Read, not just localhost side
    wdttAwaitRelay(t, done, 2*time.Second)
    if _, err := clientPeer.Write([]byte("x")); err == nil {
        t.Fatal("client socket remained writable after cancellation")
    }
    if _, err := remotePeer.Write([]byte("x")); err == nil {
        t.Fatal("netstack side remained writable after cancellation")
    }
}

func TestWDTTRelayIdleReclaimsSocketAndSlot(t *testing.T) {
    client, clientPeer := net.Pipe()
    remote, remotePeer := net.Pipe()
    defer clientPeer.Close()
    defer remotePeer.Close()
    done := make(chan struct{})
    before := wdttLife.tcpRelayIdleClosed.Load()
    go func() {wdttRelayTCP(context.Background(), client, remote, 90*time.Millisecond);close(done)}()
    wdttAwaitRelay(t, done, 2*time.Second)
    if wdttLife.tcpRelayIdleClosed.Load() <= before {t.Fatal("idle close not counted")}
}

func TestWDTTRelayProgressKeepsActiveConnectionAlive(t *testing.T) {
    client, clientPeer := net.Pipe()
    remote, remotePeer := net.Pipe()
    defer clientPeer.Close()
    defer remotePeer.Close()
    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan struct{})
    go func() {wdttRelayTCP(ctx, client, remote, 120*time.Millisecond);close(done)}()

    for i := 0; i < 7; i++ {
        _ = clientPeer.SetWriteDeadline(time.Now().Add(time.Second))
        if _, err := clientPeer.Write([]byte{'x'}); err != nil {t.Fatalf("active upload failed %d: %v",i,err)}
        _ = remotePeer.SetReadDeadline(time.Now().Add(time.Second))
        b := make([]byte,1)
        if _, err := io.ReadFull(remotePeer,b); err != nil || b[0]!='x' {
            t.Fatalf("bytes not relayed %d: %v",i,err)
        }
        select {case <-done:t.Fatal("active relay was terminated by fixed age");default:}
        time.Sleep(45*time.Millisecond)
    }
    cancel()
    wdttAwaitRelay(t, done, 2*time.Second)
}

func TestWDTTRelayTCPHalfCloseAllowsReply(t *testing.T) {
    makePair:=func() (*net.TCPConn,*net.TCPConn) {
        ln,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.IPv4(127,0,0,1),Port:0})
        if err!=nil {t.Fatal(err)}
        defer ln.Close()
        app,err:=net.DialTCP("tcp4",nil,ln.Addr().(*net.TCPAddr))
        if err!=nil {t.Fatal(err)}
        proxy,err:=ln.AcceptTCP()
        if err!=nil {t.Fatal(err)}
        return proxy,app
    }
    client,appClient:=makePair()
    remote,appServer:=makePair()
    defer appClient.Close()
    defer appServer.Close()
    done:=make(chan struct{})
    go func(){wdttRelayTCP(context.Background(),client,remote,time.Second);close(done)}()

    _=appClient.SetDeadline(time.Now().Add(2*time.Second))
    _=appServer.SetDeadline(time.Now().Add(2*time.Second))
    if _,err:=appClient.Write([]byte("request"));err!=nil {t.Fatal(err)}
    buf:=make([]byte,7)
    if _,err:=io.ReadFull(appServer,buf);err!=nil || string(buf)!="request" {t.Fatalf("request lost %v",err)}
    if err:=appClient.CloseWrite();err!=nil {t.Fatal(err)}
    // Client FIN must NOT truncate a delayed response in the other direction.
    time.Sleep(30*time.Millisecond)
    if _,err:=appServer.Write([]byte("response"));err!=nil {t.Fatal(err)}
    reply:=make([]byte,8)
    if _,err:=io.ReadFull(appClient,reply);err!=nil || string(reply)!="response" {t.Fatalf("half-closed response lost %v",err)}
    _=appServer.CloseWrite()
    wdttAwaitRelay(t,done,2*time.Second)
}
