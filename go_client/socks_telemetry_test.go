// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
    "encoding/json"
    "testing"
    "sync/atomic"
    "errors"
    "io"
    "time"
)

func TestWDTTSocksTelemetryAggregateAndNoSecrets(t *testing.T) {
    var peak atomic.Int64
    wdttTelemetryPeak(&peak,1)
    wdttTelemetryPeak(&peak,4)
    wdttTelemetryPeak(&peak,3)
    if peak.Load()!=4 {t.Fatal("telemetry peak regressed")}
    b:=wdttTelemetrySnapshot()
    if len(b)==0 {t.Fatal("telemetry snapshot empty")}
    var m map[string]any
    if err:=json.Unmarshal(b,&m);err!=nil {t.Fatal(err)}
    if m["schema"]!=float64(2) {t.Fatal("schema mismatch")}
    for _,s:=range []string{"socks_peak","udp_netstack_write_ok","udp_reply_delivered_to_proxy","go_heap_alloc_bytes"} {
        if _,ok:=m[s];!ok {t.Fatalf("missing aggregate %s",s)}
    }
    for _,s:=range []string{"password","peer","remote_ip","vk_hash","domain","wireguard_key","payload"} {
        if _,ok:=m[s];ok {t.Fatalf("forbidden diagnostic key %s",s)}
    }
}

func TestWDTTSocksLimitArm64HighMemOnly(t *testing.T) {
    cases:=[]struct{arch string; kib int64; want int}{
        {"arm64",0,32}, {"arm64",262143,32}, {"arm64",262144,64},
        {"arm64",400000,64}, {"mipsle",900000,32},
        {"mips",900000,32}, {"amd64",900000,32},
    }
    for _,c:=range cases {
        if got:=wdttSocksLimitFor(c.arch,c.kib);got!=c.want {
            t.Fatalf("arch %s available %d KiB: got %d want %d",c.arch,c.kib,got,c.want)
        }
    }
}

func TestWDTTOwnerLifecycleTelemetry(t *testing.T) {
    a:=wdttLife.tcpLt10s.Load()
    b:=wdttLife.tcp10to60s.Load()
    c:=wdttLife.tcpGe60s.Load()
    wdttLifeDuration(true,time.Second)
    wdttLifeDuration(true,10*time.Second)
    wdttLifeDuration(true,60*time.Second)
    if wdttLife.tcpLt10s.Load()!=a+1 ||
       wdttLife.tcp10to60s.Load()!=b+1 ||
       wdttLife.tcpGe60s.Load()!=c+1 {t.Fatal("wrong duration buckets")}
    up:=wdttLife.tcpToRemoteBytes.Load()
    down:=wdttLife.tcpToClientBytes.Load()
    wdttLifeTransfer(true,300,nil)
    wdttLifeTransfer(false,800,io.ErrClosedPipe)
    if wdttLife.tcpToRemoteBytes.Load()!=up+300 ||
       wdttLife.tcpToClientBytes.Load()!=down+800 {t.Fatal("wrong byte counts")}
    wdttLifeHandshakeError(io.EOF)
    wdttLifeHandshakeError(errors.New("opaque-only"))
    wdttLifeUDPControlEnd(io.EOF)
    snap:=wdttTelemetrySnapshot()
    var metrics map[string]any
    if err:=json.Unmarshal(snap,&metrics);err!=nil {t.Fatal(err)}
    for _,key:=range []string{"tcp_duration_ge_60s","tcp_relay_clean_closed","tcp_relay_idle_closed","tcp_relay_context_canceled","tcp_relay_copy_error_closed","tcp_client_to_remote_bytes","udp_control_eof","process_rss_kib","mem_available_kib","socks_handshake_active","udp_host_read_after_control_close"} {
        if _,ok:=metrics[key];!ok {t.Fatalf("missing %s",key)}
    }
    for _,key:=range []string{"peer","client_ip","remote_addr","target","password","udp_payload","vk_hash","hostname"} {
        if _,ok:=metrics[key];ok {t.Fatalf("unexpected nonaggregate key %s",key)}
    }
}
