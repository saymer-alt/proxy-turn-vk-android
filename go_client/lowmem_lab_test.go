// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
)

type lowmemSample struct {
	SOCKSActive, TCPActive, UDPActive                            int64
	Phase                                                        string `json:"phase"`
	ElapsedMS                                                    int64  `json:"elapsed_ms"`
	RSS, HWM, Swap, Available                                    uint64
	HeapAlloc, HeapInuse, HeapSys, StackInuse, TotalAlloc, NumGC uint64
	Goroutines, FDs                                              int
	PSIMemorySome, PSIIOFull                                     float64
	CgroupCurrent                                                uint64
}

func lowmemMetric(phase string, start time.Time) lowmemSample {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := lowmemSample{Phase: phase, ElapsedMS: time.Since(start).Milliseconds(), HeapAlloc: m.HeapAlloc, HeapInuse: m.HeapInuse, HeapSys: m.HeapSys, StackInuse: m.StackInuse, TotalAlloc: m.TotalAlloc, NumGC: uint64(m.NumGC), Goroutines: runtime.NumGoroutine()}
	s.SOCKSActive = wdttTelemetry.socksActive.Load()
	s.TCPActive = wdttLife.tcpActive.Load()
	s.UDPActive = wdttTelemetry.udpAssocActive.Load()
	read := func(path, key string) uint64 {
		b, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && f[0] == key {
				n, _ := strconv.ParseUint(f[1], 10, 64)
				return n
			}
		}
		return 0
	}
	s.RSS = read("/proc/self/status", "VmRSS:")
	s.HWM = read("/proc/self/status", "VmHWM:")
	s.Swap = read("/proc/self/status", "VmSwap:")
	s.Available = read("/proc/meminfo", "MemAvailable:")
	fds, _ := os.ReadDir("/proc/self/fd")
	s.FDs = len(fds)
	b, _ := os.ReadFile("/sys/fs/cgroup/memory.current")
	s.CgroupCurrent, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	psi := func(path, kind string) float64 {
		b, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && f[0] == kind {
				v, _ := strconv.ParseFloat(strings.TrimPrefix(f[1], "avg10="), 64)
				return v
			}
		}
		return 0
	}
	s.PSIMemorySome = psi("/proc/pressure/memory", "some")
	s.PSIIOFull = psi("/proc/pressure/io", "full")
	return s
}

// Opt-in TEST BINARY only. No public endpoints, credentials or shipping knobs.
// Worker scenarios are explicitly queue/socket capacity models, NOT TURN E2E.
func TestLowmemNumericLab(t *testing.T) {
	dir := os.Getenv("WDTT_LOWMEM_LAB_DIR")
	if dir == "" {
		t.Skip("isolated numeric memory lab disabled")
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("private output required")
	}
	log.SetOutput(io.Discard)
	seconds := 2
	if v := os.Getenv("WDTT_LOWMEM_SECONDS"); v != "" {
		seconds, err = strconv.Atoi(v)
		if err != nil || seconds < 1 || seconds > 1800 {
			t.Fatal("invalid bounded duration")
		}
	}
	start := time.Now()
	f, err := os.OpenFile(filepath.Join(dir, "samples.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private sample output")
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	sample := func(phase string) {
		if enc.Encode(lowmemMetric(phase, start)) != nil {
			t.Fatal("sample write")
		}
	}
	wait := func(phase string) {
		until := time.Now().Add(time.Duration(seconds) * time.Second)
		for time.Now().Before(until) {
			sample(phase)
			time.Sleep(100 * time.Millisecond)
		}
	}
	sample("idle_process")
	var priv, peer [32]byte
	priv[0] = 1
	peer[0] = 2
	pub, _ := curve25519.X25519(peer[:], curve25519.Basepoint)
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.66.66.2/32\nDNS = 10.66.66.1\nMTU = 1280\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:9\nAllowedIPs = 10.66.66.1/32\nPersistentKeepalive = 0\n", base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub))
	dev, _, err := startUserspaceWireGuard(conf)
	if err != nil {
		t.Fatal("synthetic WG init")
	}
	wait("idle_wireguard_netstack")
	for _, workers := range []int{9, 18} {
		slots := make([]*WorkerSlot, workers)
		sockets := make([]*net.UDPConn, 0, workers)
		buffers := make([][]byte, 0, workers*4)
		var actualRcv, actualSnd int
		for i := range slots {
			slots[i] = &WorkerSlot{ID: i, SendCh: make(chan []byte, workerSendBuf)}
			for j := 0; j < workerSendBuf; j++ {
				b := getPktBuf(1600)
				for k := range b {
					b[k] = 1
				}
				slots[i].SendCh <- b
			}
			c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal("local socket")
			}
			c.SetReadBuffer(socketBufSize)
			c.SetWriteBuffer(socketBufSize)
			sockets = append(sockets, c)
			raw, _ := c.SyscallConn()
			raw.Control(func(fd uintptr) {
				actualRcv, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
				actualSnd, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
			})
			for _, size := range []int{readBufSize + 80, readBufSize, readBufSize, 2000} {
				b := make([]byte, size)
				for j := range b {
					b[j] = 1
				}
				buffers = append(buffers, b)
			}
		}
		wait(fmt.Sprintf("saturated_queue_socket_model_%d", workers))
		meta, _ := json.Marshal(map[string]int{"workers": workers, "actual_rcvbuf": actualRcv, "actual_sndbuf": actualSnd, "requested_each": socketBufSize})
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("socket-buffers-%d.json", workers)), meta, 0600)
		runtime.KeepAlive(buffers)
		for _, slot := range slots {
			for len(slot.SendCh) > 0 {
				putPktBuf(<-slot.SendCh)
			}
		}
		for _, s := range sockets {
			s.Close()
		}
		runtime.GC()
		sample("after_queue_release")
	}
	for _, count := range []int{32, 64} {
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal("loopback listener")
		}
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		var peers []net.Conn
		for i := 0; i < count; i++ {
			p, e := net.Dial("tcp4", ln.Addr().String())
			if e != nil {
				t.Fatal("loopback dial")
			}
			c, e := ln.Accept()
			if e != nil {
				t.Fatal("loopback accept")
			}
			remote, other := net.Pipe()
			peers = append(peers, p, other)
			wg.Add(3)
			go func() { defer wg.Done(); wdttRelayTCP(ctx, c, remote, time.Minute) }()
			go func() { defer wg.Done(); io.Copy(io.Discard, other) }()
			go func() { defer wg.Done(); io.Copy(io.Discard, p) }()
		}
		wait(fmt.Sprintf("held_tcp_relay_%d", count))
		cancel()
		for _, p := range peers {
			p.Close()
		}
		ln.Close()
		wg.Wait()
		runtime.GC()
		sample("after_tcp_release")
	}
	key := make([]byte, 32)
	cfg := &ObfsConfig{SSRC: 1, PayloadType: 111, PaddingMax: 0}
	state := NewObfsState()
	payload := make([]byte, 1400)
	packets := 0
	var wrapped []byte
	for packets < 500000 {
		var err error
		wrapped, err = lowmemWrap(wrapped, key, payload, cfg, state)
		if err != nil {
			t.Fatal("synthetic wrap")
		}
		packets++
		if packets%5000 == 0 {
			sample("wrap_packet_churn")
		}
	}
	os.WriteFile(filepath.Join(dir, "wrap-count.json"), []byte(fmt.Sprintf("{\"packets\":%d}", packets)), 0600)
	addr := &net.UDPAddr{IP: net.IPv4(10, 66, 66, 1), Port: 1234}
	var replies [4][]byte
	for i := 0; i < 500000; i++ {
		replies[i%4], err = lowmemUDP(replies[i%4], addr, payload)
		if err != nil {
			t.Fatal("synthetic UDP encode")
		}
		if i%5000 == 0 {
			sample("udp_reply_churn_four_scratch_slots")
		}
	}
	profile, e := os.OpenFile(filepath.Join(dir, "synthetic-allocs.pprof"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal("private profile")
	}
	pprof.Lookup("allocs").WriteTo(profile, 0)
	profile.Close()
	dev.Close()
	runtime.GC()
	wait("after_all_release")
}

func BenchmarkLowmemWrap(b *testing.B) {
	key := make([]byte, 32)
	payload := make([]byte, 1400)
	cfg := &ObfsConfig{SSRC: 1, PayloadType: 111}
	s := NewObfsState()
	b.ReportAllocs()
	b.SetBytes(1400)
	var dst []byte
	for i := 0; i < b.N; i++ {
		var e error
		dst, e = lowmemWrap(dst, key, payload, cfg, s)
		if e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkLowmemUDPReply(b *testing.B) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 66, 66, 1), Port: 1234}
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(1400)
	var dst []byte
	for i := 0; i < b.N; i++ {
		var e error
		dst, e = lowmemUDP(dst, addr, payload)
		if e != nil {
			b.Fatal(e)
		}
	}
}

// Test adapters mirror each production version: candidate uses session-owned scratch.
func lowmemWrap(dst, key, payload []byte, cfg *ObfsConfig, s *ObfsState) ([]byte, error) {
	return obfsWrapPacketInto(dst, key, payload, cfg, s)
}
func lowmemUDP(dst []byte, addr *net.UDPAddr, payload []byte) ([]byte, error) {
	return wdttEncodeUDPReplyInto(dst, addr, payload)
}
