// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
    "encoding/json"
    "testing"
    "sync/atomic"
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
    if m["schema"]!=float64(1) {t.Fatal("schema mismatch")}
    for _,s:=range []string{"socks_peak","udp_netstack_write_ok","udp_reply_delivered_to_proxy","go_heap_alloc_bytes"} {
        if _,ok:=m[s];!ok {t.Fatalf("missing aggregate %s",s)}
    }
    for _,s:=range []string{"password","peer","remote_ip","vk_hash","domain","wireguard_key","payload"} {
        if _,ok:=m[s];ok {t.Fatalf("forbidden diagnostic key %s",s)}
    }
}
