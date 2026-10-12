// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const getConfSecretCanary = "SYNTHETIC_PASSWORD_PRIVATE_KEY_NEVER_EXPORT"

func TestLabGetConfResultCodes(t *testing.T) {
	tests := []struct {
		name, config, want string
		err                error
	}{
		{name: "config", config: "[Interface]\nPrivateKey = " + getConfSecretCanary, want: "GETCONF_RECEIVED"},
		{name: "no-config", want: "GETCONF_NO_CONFIG"},
		{name: "denied", err: errors.New("FATAL_AUTH: " + getConfSecretCanary), want: "GETCONF_DENIED"},
		{name: "timeout", err: fmt.Errorf("read: %w", os.ErrDeadlineExceeded), want: "GETCONF_TIMEOUT"},
		{name: "other-error", err: errors.New(getConfSecretCanary), want: "GETCONF_ERROR"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := labGetConfResult(tc.config, tc.err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLabGetConfActualReplies(t *testing.T) {
	for _, tc := range []struct {
		reply, want string
	}{
		{"NOCONF", "GETCONF_NO_CONFIG"},
		{"DENIED:wrong_password", "GETCONF_DENIED"},
		{"DENIED:device_mismatch", "GETCONF_DENIED"},
		{"[Interface]\nAddress = 10.77.0.2/32\n", "GETCONF_RECEIVED"},
	} {
		t.Run(tc.want+"-"+tc.reply[:3], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				buf := make([]byte, 256)
				n, err := server.Read(buf)
				if err == nil && string(buf[:n]) != "GETCONF:9000|lab-client|"+getConfSecretCanary {
					err = errors.New("wire request mismatch")
				}
				if err == nil {
					_, err = server.Write([]byte(tc.reply))
				}
				done <- err
			}()
			conf, err := RequestConfig(client, "9000", "lab-client", getConfSecretCanary)
			if got := labGetConfResult(conf, err); got != tc.want {
				t.Fatalf("GETCONF result: got %q, want %q", got, tc.want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLabGetConfStatusPrivateTerminal(t *testing.T) {
	labDir = t.TempDir()
	if err := os.Chmod(labDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(labDir, "getconf-status")
	labGetConfStatus("NOT_REQUESTED")
	labGetConfStatus("GETCONF_REQUESTED")
	labGetConfStatus("GETCONF_NO_CONFIG")
	labGetConfStatus("CONFIG_READY")
	labGetConfStatus("GETCONF_TIMEOUT") // late worker cannot hide confirmed WG config
	labGetConfStatus(getConfSecretCanary) // unknown codes are not persisted
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "CONFIG_READY\n" || strings.Contains(string(raw), getConfSecretCanary) {
		t.Fatal("unsafe or stale terminal GETCONF state")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("diagnostic state file is not private")
	}
	labGetConfStatus("NOT_REQUESTED") // next manual run must start with clean state
	labGetConfStatus("GETCONF_DENIED")
	raw, err = os.ReadFile(path)
	if err != nil || string(raw) != "GETCONF_DENIED\n" {
		t.Fatal("GETCONF status could not restart or retain redacted denial")
	}
}
