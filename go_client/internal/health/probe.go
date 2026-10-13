// SPDX-License-Identifier: GPL-3.0-or-later
package health

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

func ValidateTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil || len(target) > 2048 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("HEALTH_TARGET_REQUIRED_OR_INVALID")
	}
	return nil
}

type forwardDialer struct {
	reached *atomic.Bool
	dial    func(context.Context) (net.Conn, error) // private in-memory test seam
}

func (d forwardDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
func (d forwardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Ignore environment proxy configuration and every requested dial address.
	// The only host-network socket is the existing WDTT loopback SOCKS endpoint.
	var c net.Conn
	var err error
	if d.dial != nil {
		c, err = d.dial(ctx)
	} else {
		c, err = (&net.Dialer{}).DialContext(ctx, "tcp4", "127.0.0.1:1081")
	}
	if err == nil {
		d.reached.Store(true)
	}
	return c, err
}

// Probe returns only fixed codes; target, payload and upstream errors never escape.
// The owner endpoint must echo X-WDTT-Health-Nonce and send a nonempty <=4KiB body.
func Probe(ctx context.Context, target string) string {
	if ValidateTarget(target) != nil {
		return "TARGET_INVALID"
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "PROBE_RANDOM_FAILED"
	}
	return probeVia(ctx, target, hex.EncodeToString(nonce[:]), forwardDialer{reached: &atomic.Bool{}})
}

func probeVia(ctx context.Context, target, nonce string, forward forwardDialer) string {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1081", nil, forward)
	if err != nil {
		return "SOCKS_UNAVAILABLE"
	}
	tr := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext,
		DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 4096, TLSHandshakeTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "TARGET_INVALID"
	}
	req.Header.Set("X-WDTT-Health-Nonce", nonce)
	req.Header.Set("Cache-Control", "no-store, no-cache")
	resp, err := client.Do(req)
	if err != nil {
		if !forward.reached.Load() {
			return "SOCKS_UNAVAILABLE"
		}
		return "DATA_PATH_FAILED"
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 || resp.Header.Get("X-WDTT-Health-Nonce") != nonce {
		return "FRESH_RESPONSE_MISSING"
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return "DATA_PATH_FAILED"
	}
	return "FRESH_RESPONSE"
}
