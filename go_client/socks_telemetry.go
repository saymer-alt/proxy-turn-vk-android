// SPDX-License-Identifier: GPL-3.0-or-later
// Owner-only, aggregate counters: never store server/client addresses, DNS names,
// credentials, profile URI, packet content, WireGuard keys or untrusted errors.
package main

import (
    "context"
    "encoding/json"
    "runtime"
    "sync/atomic"
    "time"
)

type wdttCounters struct {
    socksAccepted atomic.Uint64
    socksActive atomic.Int64
    socksPeak atomic.Int64
    socksLimitRejected atomic.Uint64
    socksHandshakeFailed atomic.Uint64
    socksUnsupportedCmd atomic.Uint64
    tcpRequested atomic.Uint64
    tcpConnected atomic.Uint64
    tcpResolveFailed atomic.Uint64
    tcpDialFailed atomic.Uint64
    udpAssocReady atomic.Uint64
    udpAssocActive atomic.Int64
    udpAssocPeak atomic.Int64
    udpAssocFailed atomic.Uint64
    udpAssocLimitRejected atomic.Uint64
    udpClientValid atomic.Uint64
    udpClientBytes atomic.Uint64
    udpClientMalformed atomic.Uint64
    udpClientSourceRejected atomic.Uint64
    udpResolveFailed atomic.Uint64
    udpWGWriteFailed atomic.Uint64
    udpToWG atomic.Uint64
    udpRepliesRejected atomic.Uint64
    udpHostReadFailed atomic.Uint64
    udpHostWriteFailed atomic.Uint64
    udpRepliesDelivered atomic.Uint64
    udpReplyBytes atomic.Uint64
}
var wdttTelemetry wdttCounters
var wdttTelemetryStart=time.Now()

func wdttTelemetryPeak(peak *atomic.Int64,current int64) {
    for {
        old:=peak.Load()
        if current<=old || peak.CompareAndSwap(old,current) {return}
    }
}

// Snapshot numbers are cumulative per process, *not* measurements of remote
// delivery or packet loss. A successful netstack WriteTo is only local enqueue.
func wdttTelemetrySnapshot() []byte {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    info:=map[string]any{
        "schema":1,
        "uptime_seconds":int64(time.Since(wdttTelemetryStart).Seconds()),
        "socks_accepted":wdttTelemetry.socksAccepted.Load(),
        "socks_active":wdttTelemetry.socksActive.Load(),
        "socks_peak":wdttTelemetry.socksPeak.Load(),
        "socks_limit_rejected":wdttTelemetry.socksLimitRejected.Load(),
        "socks_handshake_failed":wdttTelemetry.socksHandshakeFailed.Load(),
        "socks_unsupported_command":wdttTelemetry.socksUnsupportedCmd.Load(),
        "tcp_connect_requested":wdttTelemetry.tcpRequested.Load(),
        "tcp_connected":wdttTelemetry.tcpConnected.Load(),
        "tcp_resolve_failed":wdttTelemetry.tcpResolveFailed.Load(),
        "tcp_dial_failed":wdttTelemetry.tcpDialFailed.Load(),
        "udp_associate_ready":wdttTelemetry.udpAssocReady.Load(),
        "udp_associate_active":wdttTelemetry.udpAssocActive.Load(),
        "udp_associate_peak":wdttTelemetry.udpAssocPeak.Load(),
        "udp_associate_failed":wdttTelemetry.udpAssocFailed.Load(),
        "udp_associate_limit_rejected":wdttTelemetry.udpAssocLimitRejected.Load(),
        "udp_client_valid_packets":wdttTelemetry.udpClientValid.Load(),
        "udp_client_payload_bytes":wdttTelemetry.udpClientBytes.Load(),
        "udp_client_malformed":wdttTelemetry.udpClientMalformed.Load(),
        "udp_client_source_rejected":wdttTelemetry.udpClientSourceRejected.Load(),
        "udp_resolve_failed":wdttTelemetry.udpResolveFailed.Load(),
        "udp_netstack_write_failed":wdttTelemetry.udpWGWriteFailed.Load(),
        "udp_netstack_write_ok":wdttTelemetry.udpToWG.Load(),
        "udp_reply_rejected":wdttTelemetry.udpRepliesRejected.Load(),
        "udp_host_read_failed":wdttTelemetry.udpHostReadFailed.Load(),
        "udp_host_write_failed":wdttTelemetry.udpHostWriteFailed.Load(),
        "udp_reply_delivered_to_proxy":wdttTelemetry.udpRepliesDelivered.Load(),
        "udp_reply_payload_bytes":wdttTelemetry.udpReplyBytes.Load(),
        "go_goroutines":runtime.NumGoroutine(),
        "go_heap_alloc_bytes":m.HeapAlloc,
        "go_sys_bytes":m.Sys,
        "go_gc_count":m.NumGC,
    }
    data,err:=json.MarshalIndent(info,"","  ")
    if err!=nil {return nil}
    return append(data,'\n')
}

// The security boundary is the existing 0700 directory and atomic 0600
// labWrite. Snapshot every 10s, not per packet (flash wear/CPU bounded).
func wdttStartTelemetry(ctx context.Context) func() {
    if labCfg.Mode!="socks" || labDir=="" {return func(){}}
    flush:=func(){if b:=wdttTelemetrySnapshot();len(b)>0 {_=labWrite("socks-telemetry.json",b)}}
    flush()
    stop:=make(chan struct{})
    done:=make(chan struct{})
    go func(){
        defer close(done)
        ticker:=time.NewTicker(10*time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C: flush()
            case <-stop: return
            case <-ctx.Done(): return
            }
        }
    }()
    return func(){close(stop);<-done;flush()}
}
