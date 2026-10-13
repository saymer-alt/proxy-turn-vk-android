// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestLowmemAdmissionConsistentImportRuntime(t *testing.T) {
	for _, workers := range []int{9, 16, 18} {
		minimum, _ := wdttMemoryMinimum("anonymous", workers)
		hashes := "fixture"
		if workers == 18 {
			hashes = "fixture,fixture2"
		}
		q := url.Values{"name": {"synthetic"}, "peer": {"127.0.0.1:19003"}, "hashes": {hashes}, "workers": {stringWorker(workers)}, "port": {"19000"}, "pass": {"SYNTHETIC-PASSWORD-1234"}}
		o := qOptions{Auth: "anonymous", Device: "fixture", MaxWorkers: workers, DNS: "custom:127.0.0.1"}
		raw := []byte("qwdtt://config?" + q.Encode())
		if _, _, err := qParse(raw, o, minimum-1); err == nil {
			t.Fatal("import accepted low RAM")
		}
		c, _, err := qParse(raw, o, minimum)
		if err != nil {
			t.Fatal(err)
		}
		if !labRuntimeMemoryOK(c, minimum) || labRuntimeMemoryOK(c, minimum-1) || labRuntimeMemoryOK(c, 124200) {
			t.Fatal("runtime gap or field gate bypass")
		}
	}
	for n := 1; n <= 4; n++ {
		m, _ := wdttMemoryMinimum("account", n)
		c := labConfig{Peer: "127.0.0.1:19003", Listen: "127.0.0.1:19000", Password: "SYNTHETIC-PASSWORD-1234", VK: "fixture", Auth: "account", CredsFile: "/private/fixture", DNS: "custom:127.0.0.1", Workers: n, Device: "fixture"}
		if !labRuntimeMemoryOK(c, m) || labRuntimeMemoryOK(c, m-1) {
			t.Fatal("account gate inconsistent")
		}
	}
	if _, ok := wdttMemoryMinimum("anonymous", 2); ok {
		t.Fatal("unproven lower worker plan admitted")
	}
	legacy := labConfig{Peer: "127.0.0.1:19003", Listen: "127.0.0.1:19000", Password: "SYNTHETIC-PASSWORD-1234", VK: "fixture", Auth: "anonymous", DNS: "custom:127.0.0.1", Workers: 12, Device: "fixture"}
	if !labRuntimeMemoryOK(legacy, 131072) || labRuntimeMemoryOK(legacy, 131071) || labRuntimeMemoryOK(legacy, 0) {
		t.Fatal("legacy 12-request/9-effective bypass or unknown RAM accepted")
	}
	legacy.QWDTTEffectiveWorkers = 18 // inconsistent private metadata must fail closed
	if labRuntimeMemoryOK(legacy, 1<<30) {
		t.Fatal("invalid worker metadata accepted")
	}
}

// Avoid importing fmt for the production admission path; tests use explicit counts.
func stringWorker(n int) string {
	switch n {
	case 9:
		return "9"
	case 16:
		return "16"
	case 18:
		return "18"
	}
	return "invalid"
}

func TestLowmemWrapWireEquivalentAndReuse(t *testing.T) {
	var golden struct {
		Source string            `json:"source"`
		Hashes map[string]string `json:"wire_sha256"`
	}
	data, err := os.ReadFile("testdata/lowmem-wrap-golden.json")
	if err != nil || json.Unmarshal(data, &golden) != nil || golden.Source != "dc78576bcc7593ad52b30334bd46670571753be1" {
		t.Fatal("pinned original wire fixture missing")
	}
	key := make([]byte, 32)
	for _, size := range []int{1, 128, 1400, 1600} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		cfg := &ObfsConfig{SSRC: 123, PayloadType: 111, PaddingMax: 0}
		a := &ObfsState{initSeq: 65535, initTs: 42, count: 65535}
		b := &ObfsState{initSeq: a.initSeq, initTs: a.initTs, count: a.count}
		before, err := obfsWrapPacket(key, payload, cfg, a)
		if err != nil {
			t.Fatal(err)
		}
		scratch := make([]byte, 4096)
		after, err := obfsWrapPacketInto(scratch, key, payload, cfg, b)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("wire format changed")
		}
		if &after[0] != &scratch[0] {
			t.Fatal("scratch not reused")
		}
		sum := sha256.Sum256(after)
		if hex.EncodeToString(sum[:]) != golden.Hashes[strconv.Itoa(size)] {
			t.Fatal("pinned baseline wire bytes changed")
		}
		plain := make([]byte, size)
		n, err := obfsUnwrapPacket(key, after, plain)
		if err != nil || !bytes.Equal(plain[:n], payload) {
			t.Fatal("roundtrip failed")
		}
		after[12] ^= 1
		if _, err := obfsUnwrapPacket(key, after, plain); err == nil {
			t.Fatal("authentication weakened")
		}
	}
	// Concurrent sessions have independent scratch/state; no shared output pool.
	var wg sync.WaitGroup
	for i := 0; i < 18; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var dst []byte
			s := NewObfsState()
			cfg := NewObfsConfig("video")
			plain := make([]byte, 1400)
			for j := 0; j < 100; j++ {
				var e error
				dst, e = obfsWrapPacketInto(dst, key, plain, cfg, s)
				if e != nil {
					t.Error("wrap")
				}
				out := make([]byte, 1400)
				if _, e = obfsUnwrapPacket(key, dst, out); e != nil {
					t.Error("unwrap")
				}
			}
		}()
	}
	wg.Wait()
}

func TestLowmemUDPBytesAndAllocation(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 66, 66, 1), Port: 18081}
	payload := bytes.Repeat([]byte{3}, 1400)
	original, _ := wdttEncodeUDPReply(addr, payload)
	scratch := bytes.Repeat([]byte{255}, 4096)
	got, e := wdttEncodeUDPReplyInto(scratch, addr, payload)
	if e != nil || !bytes.Equal(original, got) {
		t.Fatal("UDP framing changed / stale bytes")
	}
	allocs := testing.AllocsPerRun(1000, func() { got, e = wdttEncodeUDPReplyInto(got, addr, payload) })
	if !bytes.Equal(got[:10], []byte{0, 0, 0, 1, 10, 66, 66, 1, 70, 161}) {
		t.Fatal("RFC1928 header changed")
	}
	if allocs != 0 {
		t.Fatal("steady-state reply allocation", allocs)
	}
	if _, e = wdttEncodeUDPReplyInto(got, addr, make([]byte, wdttMaxUDPPayload+1)); e == nil {
		t.Fatal("payload cap weakened")
	}
}

type lowmemWriterToConn struct {
	net.Conn
	called bool
}

func (c *lowmemWriterToConn) WriteTo(w io.Writer) (int64, error) { c.called = true; return 0, nil }
func TestLowmemCopyDoesNotBypassProgressBuffer(t *testing.T) {
	a, b := net.Pipe()
	c, d := net.Pipe()
	defer b.Close()
	defer d.Close()
	src := &lowmemWriterToConn{Conn: a}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wdttRelayTCP(ctx, src, c, wdttTCPIdleTimeout)
	if src.called {
		t.Fatal("WriterTo bypassed the bounded buffer/progress accounting")
	}
}

// Real loopback listener + real netstack socket ownership, without a WG peer,
// transport credentials or remote packets. Repeated stop/start must reclaim
// UDP controls, packet sockets, admission slots and relay goroutines.
func TestLowmemUDPCapChurnAndListenerRestart(t *testing.T) {
	oldDir := labDir
	oldConfig := labCfg
	labDir = t.TempDir()
	// Isolate socket lifecycle from the existing concurrent atomic status-file
	// writer. Its stale-inode fail-closed race is documented separately.
	labCfg = labConfig{}
	defer func() { labDir = oldDir; labCfg = oldConfig }()
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.66.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	before := runtime.NumGoroutine()
	fds := func() int { entries, _ := os.ReadDir("/proc/self/fd"); return len(entries) }
	beforeFD := fds()
	for cycle := 0; cycle < 3; cycle++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runSocks5Server(ctx, "127.0.0.1:1081", tnet) }()
		defer cancel()
		deadline := time.Now().Add(3 * time.Second)
		for {
			probe, dialErr := net.DialTimeout("tcp4", "127.0.0.1:1081", 20*time.Millisecond)
			if dialErr == nil {
				probe.Close()
				break
			}
			select {
			case e := <-done:
				t.Fatal("listener failed", e)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("listener readiness timeout")
			}
			time.Sleep(time.Millisecond)
		}
		associate := func(expected byte) net.Conn {
			c, e := net.DialTimeout("tcp4", "127.0.0.1:1081", time.Second)
			if e != nil {
				t.Fatal(e)
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Write([]byte{5, 1, 0})
			var auth [2]byte
			if _, e = io.ReadFull(c, auth[:]); e != nil || auth != [2]byte{5, 0} {
				c.Close()
				t.Fatal("handshake failed")
			}
			_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
			var reply [10]byte
			if _, e = io.ReadFull(c, reply[:]); e != nil || reply[1] != expected {
				c.Close()
				t.Fatal("UDP cap changed", e, reply[1])
			}
			return c
		}
		for batch := 0; batch < 5; batch++ {
			var controls []net.Conn
			for i := 0; i < 4; i++ {
				controls = append(controls, associate(0))
			}
			associate(1).Close() // fifth association must fail, no silent eviction
			for _, c := range controls {
				c.Close()
			}
			deadline = time.Now().Add(2 * time.Second)
			for wdttTelemetry.udpAssocActive.Load() != 0 || wdttTelemetry.socksActive.Load() != 0 {
				if time.Now().After(deadline) {
					t.Fatal("UDP control cleanup stranded slots")
				}
				time.Sleep(time.Millisecond)
			}
		}
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("SOCKS stop stranded")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+4 || fds() > beforeFD+2 {
		if time.Now().After(deadline) {
			t.Fatal("listener churn retained descriptors/goroutines")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
