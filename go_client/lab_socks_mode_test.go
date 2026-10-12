// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleLabConfig() labConfig {
	return labConfig{
		Peer: "198.51.100.42:56000",
		Listen: "127.0.0.1:9000",
		Password: "SYNTHETIC-TEST-PASSWORD-ONLY",
		VK: "synthetic-call-hash",
		Auth: "anonymous",
		Workers: 12,
		Device: "synthetic-test-device",
	}
}

func TestLabSocksConfigIsStrictlyLoopback(t *testing.T) {
	base := sampleLabConfig()
	if err := labValidate(base); err != nil {
		t.Fatal("legacy VPN-only config must remain accepted")
	}
	base.Mode = "vpn"
	if err := labValidate(base); err != nil {
		t.Fatal("explicit vpn mode must remain accepted")
	}
	base.Mode = "socks"
	base.SocksListen = "127.0.0.1:1081"
	if err := labValidate(base); err != nil {
		t.Fatal("opt-in loopback SOCKS configuration was rejected")
	}
	for _, tc := range []struct{ mode, listen string }{
		{"socks", "0.0.0.0:1081"},
		{"socks", "192.168.1.1:1081"},
		{"socks", "[::1]:1081"},
		{"socks", "127.0.0.1:1080"},
		{"socks", "localhost:1081"},
		{"socks", ""},
		{"rawtun", "127.0.0.1:1081"},
		{"vpn", "127.0.0.1:1081"},
		{"", "127.0.0.1:1081"},
	} {
		cfg := base
		cfg.Mode, cfg.SocksListen = tc.mode, tc.listen
		if err := labValidate(cfg); err == nil {
			t.Fatalf("accepted unsafe mode %q SOCKS addr %q", tc.mode, tc.listen)
		}
	}
}

func TestLabSocksWgEndpointNeverRoutesOutsideLocalClient(t *testing.T) {
	labCfg = sampleLabConfig()
	labCfg.Mode, labCfg.SocksListen = "socks", "127.0.0.1:1081"
	good := &wgQuickConfig{
		addresses: []netip.Addr{netip.MustParseAddr("10.66.66.2")},
		dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		mtu: 1280,
		endpoint: "127.0.0.1:9000",
		allowedIPs: []string{"0.0.0.0/0"},
	}
	if !labValidateSocksWG(good) {
		t.Fatal("safe loopback WG configuration rejected")
	}
	bad := *good
	bad.endpoint = "8.8.8.8:9000"
	if labValidateSocksWG(&bad) {
		t.Fatal("accepted non-WDTT endpoint: SOCKS could bypass transport")
	}
	bad = *good
	bad.endpoint = "localhost:9000"
	if labValidateSocksWG(&bad) {
		t.Fatal("accepted hostname instead of fixed loopback")
	}
	bad = *good
	bad.addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	if labValidateSocksWG(&bad) {
		t.Fatal("accepted non-IPv4 WG interface")
	}
	bad = *good
	bad.dns = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	if labValidateSocksWG(&bad) {
		t.Fatal("accepted IPv6 tunneled DNS")
	}
	bad = *good
	bad.allowedIPs = []string{"::/0"}
	if labValidateSocksWG(&bad) {
		t.Fatal("accepted IPv6 AllowedIPs")
	}
	bad = *good
	bad.mtu = 1600
	if labValidateSocksWG(&bad) {
		t.Fatal("accepted oversized lab MTU")
	}
}

func TestLabSocksStatusPrivateAndFixed(t *testing.T) {
	labCfg = sampleLabConfig()
	labCfg.Mode = "socks"
	labDir = t.TempDir()
	if err := os.Chmod(labDir, 0700); err != nil {
		t.Fatal(err)
	}
	labSocksStatus("WAITING_FOR_WG")
	labSocksStatus("SOCKS_LISTENING")
	labSocksStatus("SYNTHETIC_PASSWORD_SHOULD_NOT_BE_WRITTEN")
	path := filepath.Join(labDir, "socks-status")
	buf, err := os.ReadFile(path)
	if err != nil || string(buf) != "SOCKS_LISTENING\n" ||
		strings.Contains(string(buf), "PASSWORD") {
		t.Fatal("unsafe SOCKS diagnostic status")
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("unsafe SOCKS status permissions")
	}
	labCfg.Mode = "vpn"
	labSocksStatus("SOCKS_STOPPED")
	buf, err = os.ReadFile(path)
	if err != nil || string(buf) != "SOCKS_LISTENING\n" {
		t.Fatal("VPN mode modified SOCKS status")
	}
}
