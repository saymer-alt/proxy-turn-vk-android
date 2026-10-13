// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in finite offered-load fixture; no Internet, credentials or admission hook.
// Overlay this identical test on the immutable baseline, replacing only factory.
func TestBoundedPipePressureLab(t *testing.T) {
	out := os.Getenv("WDTT_PIPE_LAB_REPORT")
	if out == "" {
		t.Skip("numeric pipe lab disabled")
	}
	workers, e := strconv.Atoi(os.Getenv("WDTT_PIPE_LAB_WORKERS"))
	if e != nil || (workers != 9 && workers != 18) {
		t.Fatal("worker plan")
	}
	var accepted, delivered atomic.Int64
	var wg sync.WaitGroup
	var ends []net.PacketConn
	for n := 0; n < workers; n++ {
		a, b := newBoundedPacketPipe()
		ends = append(ends, a, b)
		for _, end := range []net.PacketConn{a, b} {
			wg.Add(1)
			go func(p net.PacketConn) {
				defer wg.Done()
				packet := make([]byte, 1600)
				for i := 0; i < 4096; i++ {
					if _, e := p.WriteTo(packet, nil); e != nil {
						return
					}
					accepted.Add(1)
				}
			}(end)
		}
	}
	phases := map[string]any{}
	start := time.Now()
	time.Sleep(2 * time.Second)
	stalled := lowmemMetric("stalled", start)
	phases["stalled"] = stalled
	stalledAccepted := accepted.Load()
	for _, end := range ends {
		wg.Add(1)
		go func(p net.PacketConn) {
			defer wg.Done()
			buf := make([]byte, 1600)
			for {
				if _, _, e := p.ReadFrom(buf); e != nil {
					return
				}
				delivered.Add(1)
				time.Sleep(100 * time.Microsecond)
			}
		}(end)
	}
	time.Sleep(time.Second)
	phases["slow_consumer"] = lowmemMetric("slow_consumer", start)
	for _, end := range ends {
		end.Close()
	}
	wg.Wait()
	runtime.GC()
	phases["closed"] = lowmemMetric("closed", start)
	report := map[string]any{"workers": workers, "offered_packets_per_direction": 4096, "packet_bytes": 1600, "stall_seconds": 2, "slow_consumer_seconds": 1, "stalled_accepted": stalledAccepted, "accepted": accepted.Load(), "delivered": delivered.Load(), "phases": phases}
	data, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(out, append(data, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
