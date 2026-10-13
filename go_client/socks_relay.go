// SPDX-License-Identifier: GPL-3.0-or-later
// Bounded SOCKS TCP lifecycle in the owner-only loopback router adapter.
// No new network dial/fallback: both net.Conn values come from the existing
// Keenetic loopback accept and the WireGuard userspace netstack.
package main

import (
    "context"
    "io"
    "net"
    "sync"
    "sync/atomic"
    "time"
)

const wdttTCPIdleTimeout = 3 * time.Minute

// wdttProgressWriter registers *completed writes*, not merely read attempts.
// A long, genuinely active download/upload must not be cut off simply because
// the connection has existed for three minutes.
type wdttProgressWriter struct {
    net.Conn
    progress func()
}

// Hide source WriterTo so CopyBuffer uses the supplied 16KiB, not an extra 32KiB.
type wdttReaderOnly struct { io.Reader }

func (w wdttProgressWriter) Write(p []byte) (int, error) {
    n, err := w.Conn.Write(p)
    if n > 0 { w.progress() }
    return n, err
}

// Must interrupt both client and WireGuard-netstack sockets in response to
// cancellation, a fatal copy error, or *idle* traffic. Previously the remote
// socket was only closed *after* both io.Copy goroutines had completed, which
// could strand one goroutine and its shared SOCKS admission slot indefinitely.
// The grace for a clean TCP half-close is bounded by progress/idle time, not
// by an arbitrary short timer after the first EOF.
func wdttRelayTCP(ctx context.Context, client, remote net.Conn, idle time.Duration) {
    if idle <= 0 { idle = wdttTCPIdleTimeout }
    start := time.Now()
    var lastProgress atomic.Int64
    var reason atomic.Int32
    var once sync.Once
    closeBoth := func() { once.Do(func() {
        _ = client.Close()
        _ = remote.Close()
    }) }
    end := func(code int32) {
        if reason.CompareAndSwap(0, code) { closeBoth() }
    }

    stopOnCancel := context.AfterFunc(ctx, func() { end(3) })
    defer stopOnCancel()

    tick := idle / 4
    if tick > 5*time.Second { tick = 5*time.Second }
    if tick < 5*time.Millisecond { tick = 5*time.Millisecond }
    stopWatch := make(chan struct{})
    watchDone := make(chan struct{})
    go func() {
        defer close(watchDone)
        ticker := time.NewTicker(tick)
        defer ticker.Stop()
        for {
            select {
            case <-stopWatch:
                return
            case <-ctx.Done():
                end(3)
                return
            case <-ticker.C:
                if time.Since(start)-time.Duration(lastProgress.Load()) >= idle {
                    end(2)
                    return
                }
            }
        }
    }()

    progress := func() {
        lastProgress.Store(int64(time.Since(start)))
    }
    copied := make(chan struct{}, 2)
    transfer := func(dst, src net.Conn, towardRemote bool) {
        writer := wdttProgressWriter{Conn: dst, progress: progress}
        n, err := io.CopyBuffer(writer, wdttReaderOnly{src}, make([]byte, 16*1024))
        wdttLifeTransfer(towardRemote, n, err)
        if err != nil {
            // A failed stream cannot remain half-open forever. Closing BOTH
            // sockets also wakes a peer blocked in its opposite Read/Write.
            end(4)
        } else {
            // Preserve TCP FIN semantics for long but active responses.
            if cw, ok := dst.(interface{ CloseWrite() error }); ok {
                _ = cw.CloseWrite()
            } else {
                _ = dst.Close()
            }
        }
        copied <- struct{}{}
    }
    go transfer(remote, client, true)
    go transfer(client, remote, false)
    <-copied
    <-copied
    end(1)
    close(stopWatch)
    <-watchDone
    switch reason.Load() {
    case 1: wdttLife.tcpRelayClean.Add(1)
    case 2: wdttLife.tcpRelayIdleClosed.Add(1)
    case 3: wdttLife.tcpRelayCanceled.Add(1)
    case 4: wdttLife.tcpRelayCopyError.Add(1)
    }
}
