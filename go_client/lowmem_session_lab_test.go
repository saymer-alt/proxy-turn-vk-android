// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TEST ONLY: calls the real RunSession with the existing synthetic localhost
// fixture's credentials. No anonymous VK provider, production admission override
// or shipping environment hook. 9/18 are real simultaneous TURN/DTLS sessions.
func TestLowmemSessionLab(t *testing.T) {
	dir := os.Getenv("WDTT_LOWMEM_SESSION_DIR")
	if dir == "" {
		t.Skip("isolated session lab disabled")
	}
	workers, err := strconv.Atoi(os.Getenv("WDTT_LOWMEM_WORKERS"))
	if err != nil || workers != 9 && workers != 18 {
		t.Fatal("invalid test worker plan")
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("private output required")
	}
	log.SetOutput(io.Discard)
	labDir = dir
	t.Chdir(dir)
	labCfg = labConfig{Mode: "socks", SocksListen: "127.0.0.1:1081"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19000})
	if err != nil {
		t.Fatal("local endpoint")
	}
	defer local.Close()
	local.SetReadBuffer(socketBufSize)
	local.SetWriteBuffer(socketBufSize)
	d := NewDispatcher(ctx, local, &Stats{})
	defer func() { cancel(); local.Close(); d.Shutdown() }()
	key, err := deriveWrapKey("SYNTHETIC-LOCAL-WDTT-PASSWORD-ONLY")
	if err != nil {
		t.Fatal("synthetic key")
	}
	tp := &TurnParams{WrapKey: key, ObfsMode: "audio", Hashes: []string{"fixture", "fixture2"}}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19003}
	creds := &Credentials{User: "fixture", Pass: "SYNTHETIC-TURN-PASSWORD", TurnURLs: []string{"127.0.0.1:19002"}}
	config := make(chan string, 1)
	var wg sync.WaitGroup
	var phase atomic.Value
	phase.Store("starting_real_sessions")
	samples, err := os.OpenFile(filepath.Join(dir, "session-samples.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private samples")
	}
	defer samples.Close()
	start := time.Now()
	samplingDone := make(chan struct{})
	sampleStop := make(chan struct{})
	go func() {
		defer close(samplingDone)
		enc := json.NewEncoder(samples)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			metric := lowmemMetric(phase.Load().(string), start)
			enc.Encode(metric)
			// Test-only readiness, no shipping telemetry format change. A new
			// burst must wait for the previous TCP slots to be reclaimed.
			if os.WriteFile(filepath.Join(dir, "memory-active"), []byte(strconv.FormatInt(metric.SOCKSActive, 10)), 0600) != nil {
				t.Error("private active-slot sample")
				cancel()
				return
			}
			select {
			case <-sampleStop:
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { close(sampleStop); <-samplingDone }()
	for i := 1; i <= workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			delay := time.Duration((id-1)%9)*500*time.Millisecond + time.Duration((id-1)/9)*2*time.Second
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			RunSession(ctx, tp, peer, d, "19000", id == 1, config, id, creds, "fixture", "SYNTHETIC-LOCAL-WDTT-PASSWORD-ONLY", &Stats{})
		}(i)
	}
	var conf string
	select {
	case conf = <-config:
	case <-time.After(60 * time.Second):
		cancel()
		t.Fatal("local GETCONF timeout")
	}
	dev, tnet, err := startUserspaceWireGuard(conf)
	if err != nil {
		cancel()
		t.Fatal("local WG init")
	}
	socksDone := make(chan struct{})
	go func() { defer close(socksDone); runSocks5Server(ctx, "127.0.0.1:1081", tnet) }()
	ready := false
	until := time.Now().Add(60 * time.Second)
	for time.Now().Before(until) {
		d.mu.Lock()
		count := len(d.workers)
		d.mu.Unlock()
		b, _ := os.ReadFile(filepath.Join(dir, "socks-status"))
		if count == workers && string(b) == "SOCKS_LISTENING\n" {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		cancel()
		t.Fatal("actual worker registration or SOCKS timeout")
	}
	phase.Store("idle_real_sessions")
	os.WriteFile(filepath.Join(dir, "memory-ready"), []byte("READY\n"), 0600)
	for {
		b, _ := os.ReadFile(filepath.Join(dir, "memory-command"))
		if string(b) == "load\n" {
			phase.Store("loaded_real_sessions")
		}
		if string(b) == "idle\n" {
			phase.Store("idle_after_real_load")
		}
		if string(b) == "stop\n" || ctx.Err() != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	terminal := "STOPPED"
	if ctx.Err() == context.DeadlineExceeded {
		terminal = "TIME_LIMIT"
	}
	cancel()
	dev.Close()
	local.Close()
	<-socksDone
	wg.Wait()
	// Optional synthetic-only alloc profile, never exported by CI. Separate
	// profiling runs are excluded from the paired RSS/latency comparison.
	if profileDir := os.Getenv("WDTT_LOWMEM_SESSION_PROFILE_DIR"); profileDir != "" {
		info, e := os.Stat(profileDir)
		if e != nil || info.Mode().Perm() != 0700 {
			t.Fatal("private profile directory")
		}
		f, e := os.OpenFile(filepath.Join(profileDir, "session-allocs.pprof"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal("private allocation profile")
		}
		if e = pprof.Lookup("allocs").WriteTo(f, 0); e != nil {
			f.Close()
			t.Fatal("allocation profile write")
		}
		f.Close()
	}
	phase.Store("after_real_session_release")
	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, "memory-finished"), []byte(terminal+"\n"), 0600)
}
