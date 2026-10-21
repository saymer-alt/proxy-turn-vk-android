// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWDTTLegacyShortPassOwnerOptInAndWRAP(t *testing.T) {
	// All are synthetic public-like tokens. No real user credentials.
	passes := []string{"Zp8N2q6mA1sX", "Zp8N2q6mA1sX3", "Zp8N2q6mA1sX345"}
	for _, pass := range passes {
		t.Run(pass, func(t *testing.T) {
			raw := strings.Replace(wdttTestURI("oneHash"), wdttColonCanary, pass, 1)
			opts := qAnonOpts()
			opts.MaxWorkers = 18
			_, _, err := wdttColonParse([]byte(raw), opts, 200000)
			if err == nil || !strings.Contains(err.Error(), "SHORT_PASSWORD_OPT_IN_REQUIRED") {
				t.Fatal("short secret admitted without a deliberate flag")
			}
			opts.AllowLegacyShortPassword = true
			got, _, err := wdttColonParse([]byte(raw), opts, 200000)
			if err != nil {
				t.Fatalf("explicitly opted-in password denied: %v", err)
			}
			if got.Password != pass || !got.WDTTLegacyShortPassword ||
				got.Auth != "anonymous" || got.Mode != "socks" ||
				got.SocksListen != "127.0.0.1:1081" || got.Workers != 18 ||
				labValidate(got) != nil {
				t.Fatal("secret changed, unsafe mode or runtime gate rejected it")
			}
			// The ordinary qWDTT link importer NEVER enables the policy even
			// for otherwise identical syntactically supported workgroups.
			baseURI, parseErr := url.Parse(qURI("18", "oneHash"))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			values := baseURI.Query()
			values.Set("pass", pass)
			baseURI.RawQuery = values.Encode()
			normalOpts := qAnonOpts()
			normalOpts.MaxWorkers = 18
			// Ordinary qWDTT's private importer never sets opt-in.
			if _, _, err := qParse([]byte(baseURI.String()), normalOpts, 200000); err == nil {
				t.Fatal("ordinary qWDTT path accepted short password")
			}
			broken := got
			broken.WDTTLegacyShortPassword = false
			if labValidate(broken) == nil {
				t.Fatal("runtime accepted short pass without explicit config annotation")
			}
			broken = got
			broken.Mode = "vpn"
			broken.SocksListen = ""
			if labValidate(broken) == nil {
				t.Fatal("short pass escaped loopback SOCKS policy")
			}
			broken = got
			broken.Auth = "account"
			if labValidate(broken) == nil {
				t.Fatal("short pass escaped anonymous-only policy")
			}
			broken = got
			broken.Password = wdttColonCanary
			if labValidate(broken) == nil {
				t.Fatal("marker accepted with nonlegacy long password")
			}
		})
	}
	// Independently computed HKDF-SHA256 (synthetic 12-character input):
	// PRK = HMAC_SHA256("WDTT-WRAP-v1", password);
	// OKM = HMAC_SHA256(PRK, "rtp-obfs/chacha20poly1305" + 0x01).
	key, err := deriveWrapKey("Zp8N2q6mA1sX")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != "4ca4e44b18d0696fe2a3741dfad9fe28ed5db990b073b7028a7c55dd34933c6c" {
		t.Fatal("unexpected WRAP HKDF output for server-issued short token")
	}
}

func TestWDTTLegacyShortPassRejectUnsafeAndKeepMemoryFloor(t *testing.T) {
	opts := qAnonOpts()
	opts.MaxWorkers = 18
	opts.AllowLegacyShortPassword = true
	for _, pass := range []string{
		"Zp8N2q6mA1s",     // 11 chars
		"Zp8N2q6mA1s@",    // punctuation
		"Zp8N2q6m A1s",    // whitespace
		"Zp8N2q6mA1s\n",  // control
		"Zp8N2q6mA1sX:",  // ambiguous colon separator
		"Zp8N2q6mA1sX___", // 15 characters with '_'
	} {
		raw := strings.Replace(wdttTestURI("oneHash"), wdttColonCanary, pass, 1)
		if _, _, err := wdttColonParse([]byte(raw), opts, 200000); err == nil {
			t.Fatal("unsafe legacy token admitted")
		}
	}
	short := strings.Replace(wdttTestURI("oneHash"), wdttColonCanary, "Zp8N2q6mA1sX", 1)
	if _, _, err := wdttColonParse([]byte(short), opts, 155647); err == nil {
		t.Fatal("18/1 minimum MemAvailable relaxed by password exception")
	}
	if _, _, err := wdttColonParse([]byte(short), opts, 155648); err != nil {
		t.Fatalf("expected exact 18/1 RAM floor: %v", err)
	}
}

func TestWDTTLegacyShortPassPrivateCLI(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := sock.LocalAddr().(*net.UDPAddr).Port
	sock.Close()
	raw := strings.Replace(wdttTestURI("oneHash"), wdttColonCanary, "Zp8N2q6mA1sX", 1)
	raw = strings.Replace(raw, ":19000:", ":"+fmtInt(port)+":", 1)
	input, output := filepath.Join(d, "profile-private.uri"), filepath.Join(d, "short-private.json")
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	argv := []string{
		"-uri-file", input, "-output-file", output,
		"-auth", "anonymous", "-device", "synthetic-device",
		"-max-workers", "18", "-dns", "yandex",
	}
	var stdout, stderr bytes.Buffer
	if rc := wdttColonImportCLI(argv, &stdout, &stderr); rc != 78 {
		t.Fatalf("short pass should require explicit opt-in, rc=%d", rc)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("private output created without opt-in")
	}
	argv = append(argv, "--allow-legacy-short-password")
	stdout.Reset()
	stderr.Reset()
	if rc := wdttColonImportCLI(argv, &stdout, &stderr); rc != 0 {
		t.Fatalf("explicit private short pass import rejected: %d", rc)
	}
	if strings.Contains(stdout.String()+stderr.String(), "Zp8N2q6mA1sX") {
		t.Fatal("secret printed in importer response")
	}
	st, err := os.Stat(output)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("short pass output is not 0600")
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var parsed labConfig
	if json.Unmarshal(b, &parsed) != nil || parsed.Password != "Zp8N2q6mA1sX" ||
		!parsed.WDTTLegacyShortPassword || labValidate(parsed) != nil {
		t.Fatal("private short pass not preserved and guarded")
	}
	stdout.Reset()
	stderr.Reset()
	if rc := wdttColonImportCLI(argv, &stdout, &stderr); rc != 78 {
		t.Fatal("unsafe overwrite allowed with opt-in")
	}
}
