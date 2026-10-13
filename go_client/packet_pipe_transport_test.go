// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// Run only with the existing synthetic loopback TURN/DTLS fixture in a fresh netns.
func TestBoundedTransportPathsLab(t *testing.T) {
	if os.Getenv("WDTT_PIPE_TRANSPORT_LAB") != "1" {
		t.Skip("isolated transport paths disabled")
	}
	key, err := deriveWrapKey("SYNTHETIC-LOCAL-WDTT-PASSWORD-ONLY")
	if err != nil {
		t.Fatal(err)
	}
	tp := &TurnParams{WrapKey: key, ObfsMode: "audio"}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19003}
	creds := &Credentials{User: "fixture", Pass: "SYNTHETIC-TURN-PASSWORD", TurnURLs: []string{"127.0.0.1:19002"}}
	before := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	for cycle := 0; cycle < 10; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err = RunPing(ctx, tp, peer, creds)
		cancel()
		if err != nil {
			t.Fatal("synthetic ping", err)
		}
		wrong := *tp
		wrong.WrapKey = append([]byte(nil), key...)
		wrong.WrapKey[0] ^= 1
		ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err = RunPing(ctx, &wrong, peer, creds)
		cancel()
		if err == nil {
			t.Fatal("wrong WRAP succeeded")
		}
		ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err = RunSession(ctx, &wrong, peer, nil, "19000", false, nil, cycle, creds, "fixture", "synthetic", &Stats{})
		cancel()
		if err == nil {
			t.Fatal("wrong WRAP session succeeded")
		}
	}
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) && runtime.NumGoroutine() > before+4 {
		time.Sleep(10 * time.Millisecond)
	}
	afterFDs, _ := os.ReadDir("/proc/self/fd")
	if runtime.NumGoroutine() > before+4 || len(afterFDs) > len(fds)+1 {
		t.Fatalf("cleanup goroutines %d -> %d, FDs %d -> %d", before, runtime.NumGoroutine(), len(fds), len(afterFDs))
	}
}
