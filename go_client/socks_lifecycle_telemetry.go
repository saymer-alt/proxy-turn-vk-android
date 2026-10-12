// SPDX-License-Identifier: GPL-3.0-or-later
// Fixed numeric aggregate-only owner-lab counters; never store network
// destinations, payloads, secrets or upstream diagnostic strings.
package main

import (
    "errors"
    "io"
    "net"
    "os"
    "strconv"
    "strings"
    "sync/atomic"
    "time"
)

type wdttLifecycleCounters struct {
    handshakeActive atomic.Int64
    handshakePeak atomic.Int64
    handshakeEOF atomic.Uint64
    handshakeTimeout atomic.Uint64
    handshakeOther atomic.Uint64
    tcpActive atomic.Int64
    tcpPeak atomic.Int64
    tcpCompleted atomic.Uint64
    tcpReplyFailed atomic.Uint64
    tcpLt10s atomic.Uint64
    tcp10to60s atomic.Uint64
    tcpGe60s atomic.Uint64
    tcpToRemoteBytes atomic.Uint64
    tcpToClientBytes atomic.Uint64
    tcpToRemoteErrors atomic.Uint64
    tcpToClientErrors atomic.Uint64
    tcpToRemoteTimeouts atomic.Uint64
    tcpToClientTimeouts atomic.Uint64
    udpCompleted atomic.Uint64
    udpLt10s atomic.Uint64
    udp10to60s atomic.Uint64
    udpGe60s atomic.Uint64
    udpNoClientData atomic.Uint64
    udpControlEOF atomic.Uint64
    udpControlOther atomic.Uint64
    udpHostReadAfterControlClose atomic.Uint64
    udpHostReadUnexpected atomic.Uint64
}
var wdttLife wdttLifecycleCounters

func wdttLifeDuration(tcp bool, d time.Duration) {
    switch {
    case tcp && d<10*time.Second: wdttLife.tcpLt10s.Add(1)
    case tcp && d<time.Minute: wdttLife.tcp10to60s.Add(1)
    case tcp: wdttLife.tcpGe60s.Add(1)
    case d<10*time.Second: wdttLife.udpLt10s.Add(1)
    case d<time.Minute: wdttLife.udp10to60s.Add(1)
    default: wdttLife.udpGe60s.Add(1)
    }
}
func wdttLifeHandshakeError(err error) {
    if errors.Is(err,io.EOF)||errors.Is(err,io.ErrUnexpectedEOF) {
        wdttLife.handshakeEOF.Add(1)
    } else if ne,ok:=err.(net.Error);ok && ne.Timeout() {
        wdttLife.handshakeTimeout.Add(1)
    } else { wdttLife.handshakeOther.Add(1) }
}
func wdttLifeUDPControlEnd(err error) {
    if errors.Is(err,io.EOF) {wdttLife.udpControlEOF.Add(1)
    } else {wdttLife.udpControlOther.Add(1)}
}
func wdttLifeTransfer(toRemote bool, n int64, err error) {
    if n<0 {n=0}
    if toRemote {
        wdttLife.tcpToRemoteBytes.Add(uint64(n))
        if err!=nil {
            wdttLife.tcpToRemoteErrors.Add(1)
            if ne,ok:=err.(net.Error);ok && ne.Timeout() {wdttLife.tcpToRemoteTimeouts.Add(1)}
        }
    } else {
        wdttLife.tcpToClientBytes.Add(uint64(n))
        if err!=nil {
            wdttLife.tcpToClientErrors.Add(1)
            if ne,ok:=err.(net.Error);ok && ne.Timeout() {wdttLife.tcpToClientTimeouts.Add(1)}
        }
    }
}
// Parse Linux numeric procfs fields only; absent or unavailable yields zero.
func wdttLifeProcKiB(field string) int64 {
    b,err:=os.ReadFile("/proc/self/status")
    if err!=nil {return 0}
    for _,line:=range strings.Split(string(b),"\n") {
        f:=strings.Fields(line)
        if len(f)!=3||f[0]!=field+":"||f[2]!="kB" {continue}
        v,e:=strconv.ParseInt(f[1],10,64)
        if e==nil&&v>=0 {return v}
    }
    return 0
}
func wdttLifeAddSnapshot(m map[string]any) {
    m["socks_handshake_active"]=wdttLife.handshakeActive.Load()
    m["socks_handshake_peak"]=wdttLife.handshakePeak.Load()
    m["socks_handshake_eof"]=wdttLife.handshakeEOF.Load()
    m["socks_handshake_timeout"]=wdttLife.handshakeTimeout.Load()
    m["socks_handshake_other"]=wdttLife.handshakeOther.Load()
    m["tcp_active"]=wdttLife.tcpActive.Load()
    m["tcp_peak"]=wdttLife.tcpPeak.Load()
    m["tcp_completed"]=wdttLife.tcpCompleted.Load()
    m["tcp_reply_failed"]=wdttLife.tcpReplyFailed.Load()
    m["tcp_duration_lt_10s"]=wdttLife.tcpLt10s.Load()
    m["tcp_duration_10_to_60s"]=wdttLife.tcp10to60s.Load()
    m["tcp_duration_ge_60s"]=wdttLife.tcpGe60s.Load()
    m["tcp_client_to_remote_bytes"]=wdttLife.tcpToRemoteBytes.Load()
    m["tcp_remote_to_client_bytes"]=wdttLife.tcpToClientBytes.Load()
    m["tcp_client_to_remote_copy_errors"]=wdttLife.tcpToRemoteErrors.Load()
    m["tcp_remote_to_client_copy_errors"]=wdttLife.tcpToClientErrors.Load()
    m["tcp_client_to_remote_copy_timeouts"]=wdttLife.tcpToRemoteTimeouts.Load()
    m["tcp_remote_to_client_copy_timeouts"]=wdttLife.tcpToClientTimeouts.Load()
    m["udp_completed"]=wdttLife.udpCompleted.Load()
    m["udp_duration_lt_10s"]=wdttLife.udpLt10s.Load()
    m["udp_duration_10_to_60s"]=wdttLife.udp10to60s.Load()
    m["udp_duration_ge_60s"]=wdttLife.udpGe60s.Load()
    m["udp_completed_without_client_data"]=wdttLife.udpNoClientData.Load()
    m["udp_control_eof"]=wdttLife.udpControlEOF.Load()
    m["udp_control_other_error"]=wdttLife.udpControlOther.Load()
    m["udp_host_read_after_control_close"]=wdttLife.udpHostReadAfterControlClose.Load()
    m["udp_host_read_unexpected_error"]=wdttLife.udpHostReadUnexpected.Load()
    m["process_rss_kib"]=wdttLifeProcKiB("VmRSS")
    m["process_rss_high_water_kib"]=wdttLifeProcKiB("VmHWM")
    m["mem_available_kib"]=qMemory()
}
