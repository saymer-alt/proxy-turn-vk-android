// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/cbeuw/connutil"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func pipeResult(t *testing.T, ch <-chan error, want error) {
	t.Helper()
	select {
	case err := <-ch:
		if !errors.Is(err, want) {
			t.Fatalf("got %v want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked operation did not return")
	}
}
func TestBoundedPipeRecords(t *testing.T) {
	a, b := newBoundedPacketPipe()
	defer a.Close()
	for _, size := range []int{0, 1, 1100, 1600, 1680, 16384, 65535, 65536} {
		data := bytes.Repeat([]byte{byte(size)}, size)
		if n, e := a.WriteTo(data, nil); e != nil || n != size {
			t.Fatal(n, e)
		}
		if size > 0 {
			if _, _, e := b.ReadFrom(make([]byte, size-1)); !errors.Is(e, io.ErrShortBuffer) {
				t.Fatal(e)
			}
		}
		out := make([]byte, size)
		if n, _, e := b.ReadFrom(out); e != nil || n != size || !bytes.Equal(out, data) {
			t.Fatal(n, e)
		}
	}
	if _, e := a.WriteTo(make([]byte, packetPipeBytes+1), nil); !errors.Is(e, connutil.ErrWriteToLarge) {
		t.Fatal(e)
	}
}
func TestBoundedPipeBackpressure(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, size := range []int{0, 1100, packetPipeBytes} {
			a, b := newBoundedPacketPipe()
			if reverse {
				a, b = b, a
			}
			max := packetPipePackets
			if size > 0 && packetPipeBytes/size < max {
				max = packetPipeBytes / size
			}
			for i := 0; i < max; i++ {
				if _, e := a.WriteTo(make([]byte, size), nil); e != nil {
					t.Fatal(e)
				}
			}
			done := make(chan error, 1)
			go func() { _, e := a.WriteTo(make([]byte, size), nil); done <- e }()
			select {
			case e := <-done:
				t.Fatal("no backpressure", e)
			case <-time.After(10 * time.Millisecond):
			}
			if _, _, e := b.ReadFrom(make([]byte, size)); e != nil {
				t.Fatal(e)
			}
			pipeResult(t, done, nil)
			a.Close()
		}
	}
}
func TestBoundedPipeDeadlineCancelClose(t *testing.T) {
	for cycle := 0; cycle < 100; cycle++ {
		a, b := newBoundedPacketPipe()
		for i := 0; i < packetPipePackets; i++ {
			a.WriteTo(nil, nil)
		}
		write := make(chan error, 1)
		read := make(chan error, 1)
		go func() { _, e := a.WriteTo(nil, nil); write <- e }()
		go func() { _, _, e := a.ReadFrom(nil); read <- e }()
		switch cycle % 3 {
		case 0:
			a.SetDeadline(time.Now().Add(time.Millisecond))
			pipeResult(t, write, os.ErrDeadlineExceeded)
			pipeResult(t, read, os.ErrDeadlineExceeded)
		case 1:
			ctx, cancel := context.WithCancel(context.Background())
			stop := context.AfterFunc(ctx, func() { b.Close() })
			cancel()
			pipeResult(t, write, io.ErrClosedPipe)
			pipeResult(t, read, io.ErrClosedPipe)
			stop()
		case 2:
			b.Close()
			pipeResult(t, write, io.ErrClosedPipe)
			pipeResult(t, read, io.ErrClosedPipe)
		}
		a.Close()
		b.Close()
	}
	a, b := newBoundedPacketPipe()
	defer a.Close()
	a.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, e := a.WriteTo(nil, nil); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	a.SetWriteDeadline(time.Time{})
	if _, e := a.WriteTo(nil, nil); e != nil {
		t.Fatal(e)
	}
	b.ReadFrom(nil)
}
func TestBoundedPipeWorkers(t *testing.T) {
	before := runtime.NumGoroutine()
	for _, workers := range []int{9, 18} {
		var wg sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			a, b := newBoundedPacketPipe()
			a.SetDeadline(time.Now().Add(5 * time.Second))
			b.SetDeadline(time.Now().Add(5 * time.Second))
			wg.Add(2)
			go func() {
				defer wg.Done()
				for n := 0; n < 2000; n++ {
					if _, e := a.WriteTo([]byte{byte(n)}, nil); e != nil {
						t.Error(e)
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				defer a.Close()
				buf := make([]byte, 1)
				for n := 0; n < 2000; n++ {
					size, _, e := b.ReadFrom(buf)
					if e != nil {
						t.Error(e)
						return
					}
					if size != 1 || buf[0] != byte(n) {
						t.Error("record ordering")
					}
					if n%100 == 0 {
						time.Sleep(time.Microsecond)
					}
				}
			}()
		}
		wg.Wait()
	}
	if runtime.NumGoroutine() > before+4 {
		t.Fatal("goroutines did not return")
	}
}

func TestBoundedPingCancelledTURN(t *testing.T) {
	listener, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := RunPing(ctx, &TurnParams{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, &Credentials{User: "synthetic", Pass: "synthetic", TurnURLs: []string{listener.LocalAddr().String()}})
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled ping succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("TURN cancellation hung")
	}
}

// Reproducer: the dependency's byte limit does not bound packet metadata.
func TestLimitedPipeZeroPacketReproducer(t *testing.T) {
	a, b := connutil.LimitedAsyncPacketPipe(1600)
	defer a.Close()
	defer b.Close()
	for i := 0; i < 100000; i++ {
		if _, err := a.Write(nil); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	t.Log("100000 empty packets accepted without a consumer despite 1600-byte soft limit")
}
