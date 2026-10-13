// SPDX-License-Identifier: GPL-3.0-or-later
package health

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

// A complete SOCKS5 CONNECT + HTTP exchange over net.Pipe: no OS/network dial.
func fixture(t *testing.T, echo bool, requests *atomic.Int32) forwardDialer {
	t.Helper()
	return forwardDialer{reached: &atomic.Bool{}, dial: func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			var greeting [3]byte
			if _, e := io.ReadFull(s, greeting[:]); e != nil {
				return
			}
			if greeting != [3]byte{5, 1, 0} {
				t.Error("unexpected SOCKS authentication")
				return
			}
			if _, e := s.Write([]byte{5, 0}); e != nil {
				return
			}
			var h [4]byte
			if _, e := io.ReadFull(s, h[:]); e != nil {
				return
			}
			if h[0] != 5 || h[1] != 1 {
				t.Error("expected CONNECT")
				return
			}
			length := 0
			switch h[3] {
			case 1:
				length = 4
			case 4:
				length = 16
			case 3:
				var n [1]byte
				if _, e := io.ReadFull(s, n[:]); e != nil {
					return
				}
				length = int(n[0])
			default:
				return
			}
			if _, e := io.CopyN(io.Discard, s, int64(length+2)); e != nil {
				return
			}
			if _, e := s.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}); e != nil {
				return
			}
			r, e := http.ReadRequest(bufio.NewReader(s))
			if e != nil {
				return
			}
			requests.Add(1)
			nonce := "OLD_STATUS_CANARY"
			if echo {
				nonce = r.Header.Get("X-WDTT-Health-Nonce")
			}
			fmt.Fprintf(s, "HTTP/1.1 200 OK\r\nX-WDTT-Health-Nonce: %s\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", nonce)
		}()
		return c, nil
	}}
}

func TestFreshSOCKSResponseAndRejectOldNonce(t *testing.T) {
	var count atomic.Int32
	for i, echo := range []bool{true, false, true} {
		r := probeVia(context.Background(), "http://owner.invalid/check", "nonce-new", fixture(t, echo, &count))
		want := "FRESH_RESPONSE"
		if !echo {
			want = "FRESH_RESPONSE_MISSING"
		}
		if r != want {
			t.Fatal(i, r)
		}
	}
	if count.Load() != 3 {
		t.Fatal("response/connection reused")
	}
}

func TestProbeCancellationAndExplicitTarget(t *testing.T) {
	for _, target := range []string{"", "ftp://owner.invalid", "https://user:secret@owner.invalid", "https://owner.invalid/#secret"} {
		if ValidateTarget(target) == nil {
			t.Fatal("unsafe target accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := forwardDialer{reached: &atomic.Bool{}, dial: func(ctx context.Context) (net.Conn, error) { cancel(); <-ctx.Done(); return nil, ctx.Err() }}
	if probeVia(ctx, "http://owner.invalid/check", "nonce", f) != "SOCKS_UNAVAILABLE" {
		t.Fatal("cancelled dial succeeded")
	}
}

func TestCancellationDuringSOCKSHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, s := net.Pipe()
	defer s.Close()
	finished := make(chan struct{})
	go func() { defer close(finished); var greeting [3]byte; io.ReadFull(s, greeting[:]); cancel() }()
	f := forwardDialer{reached: &atomic.Bool{}, dial: func(context.Context) (net.Conn, error) { return c, nil }}
	if probeVia(ctx, "http://owner.invalid/check", "nonce", f) == "FRESH_RESPONSE" {
		t.Fatal("cancelled handshake accepted")
	}
	<-finished
}
