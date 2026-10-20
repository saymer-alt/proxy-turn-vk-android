// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wdttColonCanary = "SYNTHETIC_COLON_PASSWORD_16MIN"

func wdttTestURI(hashes string) string {
	return "wdtt://192.0.2.77:56000:56001:19000:" + wdttColonCanary + ":" + hashes
}

func TestWDTTColonAnonymousOfflineVariants(t *testing.T) {
	for _, tc := range []struct {
		name, hashes string
		workers      int
		wantRuntime  int
	}{
		{"nine_one", "oneHash", 9, 12},
		{"sixteen_one", "oneHash", 16, 16},
		{"eighteen_one", "oneHash", 18, 18},
		{"eighteen_two", "oneHash,twoHash", 18, 18},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := qAnonOpts()
			o.MaxWorkers = tc.workers
			cfg, name, err := wdttColonParse([]byte(wdttTestURI(tc.hashes)), o, 200000)
			if err != nil {
				t.Fatalf("synthetic WDTT import rejected: %v", err)
			}
			if name != "WDTT" || cfg.Peer != "192.0.2.77:56000" ||
				cfg.Listen != "127.0.0.1:19000" ||
				cfg.Auth != "anonymous" || cfg.Workers != tc.wantRuntime ||
				cfg.QWDTTRequestedWorkers != tc.workers ||
				cfg.QWDTTEffectiveWorkers != tc.workers ||
				cfg.VK != tc.hashes || cfg.Password != wdttColonCanary ||
				cfg.Mode != "socks" || cfg.SocksListen != "127.0.0.1:1081" ||
				labValidate(cfg) != nil {
				t.Fatal("unexpected imported private owner-lab profile")
			}
			floor, admitted := wdttMemoryMinimum("anonymous", tc.workers)
			if !admitted || floor < 1 {
				t.Fatal("missing worker/memory admission")
			}
			if _, _, err := wdttColonParse([]byte(wdttTestURI(tc.hashes)), o, floor-1); err == nil {
				t.Fatal("memory admission relaxed")
			}
			if _, _, err := wdttColonParse([]byte(wdttTestURI(tc.hashes)), o, floor); err != nil {
				t.Fatalf("memory admission floor rejected: %v", err)
			}
		})
	}
}

func TestWDTTColonPrivacyAndStrictGrammar(t *testing.T) {
	o := qAnonOpts()
	o.MaxWorkers = 18
	valid := wdttTestURI("oneHash")
	invalid := []string{
		"", "https://example.invalid/", "wdtt://", "wdtt://badhost:56000:56001:19000:" + wdttColonCanary + ":oneHash",
		"wdtt://0.0.0.0:56000:56001:19000:" + wdttColonCanary + ":oneHash",
		"wdtt://224.0.0.1:56000:56001:19000:" + wdttColonCanary + ":oneHash",
		"wdtt://192.0.2.77:0:56001:19000:" + wdttColonCanary + ":oneHash",
		"wdtt://192.0.2.77:56000:0:19000:" + wdttColonCanary + ":oneHash",
		"wdtt://192.0.2.77:56000:56001:0:" + wdttColonCanary + ":oneHash",
		"wdtt://192.0.2.77:56000:56001:19000:shortpass:oneHash",
		"wdtt://192.0.2.77:56000:56001:19000:" + wdttColonCanary + ":VK_HASH",
		"wdtt://192.0.2.77:56000:56001:19000:" + wdttColonCanary + ":oneHash,oneHash",
		"wdtt://192.0.2.77:56000:56001:19000:" + wdttColonCanary + ":oneHash,twoHash,thirdHash",
		"wdtt://192.0.2.77:56000:56001:19000:" + wdttColonCanary + ":oneHash:extra",
		"wdtt://192.0.2.77:56000:56001:19000:colon:inside:oneHash",
		valid + "?unknown=x", valid + "#bad%ZZ", valid + "#label#duplicate",
		valid + "\n\n", valid + "\r", valid + "\x00",
		strings.Repeat("x", 8193),
		"wdtt://eyJpcCI6IjE5Mi4wLjIuNzcifQ==", // distinct panel JSON dialect: reject, don't guess
	}
	for _, link := range invalid {
		_, _, err := wdttColonParse([]byte(link), o, 200000)
		if err == nil {
			t.Fatal("invalid colon link admitted")
		}
		if strings.Contains(err.Error(), wdttColonCanary) ||
			strings.Contains(err.Error(), "192.0.2.77") ||
			strings.Contains(err.Error(), "oneHash") {
			t.Fatal("error leaked private link")
		}
	}
	decoded, label, err := wdttColonParse([]byte(valid+"#%D0%A2%D0%B5%D1%81%D1%82\r\n"), o, 200000)
	if err != nil || label != "Тест" || decoded.VK != "oneHash" {
		t.Fatalf("safe label decoding rejected: %v", err)
	}
	o.Auth = "account"
	if _, _, err := wdttColonParse([]byte(valid), o, 200000); err == nil {
		t.Fatal("ambiguous implicit account auth admitted")
	}
	o.Auth = "anonymous"
	o.MaxWorkers = 0
	if _, _, err := wdttColonParse([]byte(valid), o, 200000); err == nil {
		t.Fatal("implicit worker default admitted")
	}
}

func TestWDTTColonPrivateImportLifecycleAndCLI(t *testing.T) {
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
	raw := strings.Replace(wdttTestURI("oneHash"), ":19000:", ":"+fmtInt(port)+":", 1)
	input := filepath.Join(d, "private-wdtt.uri")
	output := filepath.Join(d, "private-wdtt-config.json")
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := qAnonOpts()
	o.MaxWorkers = 18
	o.Input, o.Output = input, output
	if err := wdttColonImport(o); err != nil {
		t.Fatalf("private import rejected: %v", err)
	}
	st, err := os.Stat(output)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("output isn't a private 0600 file")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var cfg labConfig
	if json.Unmarshal(got, &cfg) != nil || cfg.Mode != "socks" ||
		cfg.SocksListen != "127.0.0.1:1081" ||
		cfg.Workers != 18 || cfg.VK != "oneHash" || labValidate(cfg) != nil {
		t.Fatal("generated lab config rejected by runtime")
	}
	if err := wdttColonImport(o); err == nil {
		t.Fatal("existing output overwritten")
	}
	got2, _ := os.ReadFile(output)
	if !bytes.Equal(got, got2) {
		t.Fatal("attempt to overwrite changed prior private config")
	}
	var stdout, stderr bytes.Buffer
	second := filepath.Join(d, "from-cli.json")
	code := wdttColonImportCLI([]string{
		"-uri-file", input,
		"-output-file", second,
		"-auth", "anonymous",
		"-device", "synthetic-lab-device",
		"-dns", "yandex",
		"-max-workers", "18",
	}, &stdout, &stderr)
	if code != 0 || strings.Contains(stdout.String()+stderr.String(), wdttColonCanary) {
		t.Fatalf("private command failed or leaked: code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	code = wdttColonImportCLI([]string{"-pass", wdttColonCanary}, &stdout, &stderr)
	if code != 78 || strings.Contains(stdout.String()+stderr.String(), wdttColonCanary) {
		t.Fatal("secret-bearing argv accepted or echoed")
	}
	// The caller's private file must not be printed by any rejected path.
	os.Chmod(input, 0644)
	if wdttColonImport(o) == nil {
		t.Fatal("world-readable private input accepted")
	}
}
