// SPDX-License-Identifier: GPL-3.0-or-later
package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxIdentityTelemetryAndOldStatus(t *testing.T) {
	profile := t.TempDir()
	if err := os.Chmod(profile, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(profile)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	l, e := Attach(os.Getpid(), exe, profile)
	if e != nil {
		t.Fatal(e)
	}
	put := func(name string, b []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(profile, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	stamp := func(name string, at time.Time) {
		t.Helper()
		if e := os.Chtimes(filepath.Join(profile, name), at, at); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := json.Marshal(map[string]any{"schema": 2, "uptime_seconds": int64(time.Since(l.Started).Seconds())})
	put("socks-telemetry.json", b)
	put("status", []byte("TIME_LIMIT\n"))
	stamp("status", l.Started.Add(-time.Second))
	o := l.Observe(time.Now())
	if !o.Alive || !o.Verified || !o.TelemetryFresh || o.TimeLimit {
		t.Fatal(o)
	}
	stamp("socks-telemetry.json", time.Now().Add(-26*time.Second))
	if l.Observe(time.Now()).TelemetryFresh {
		t.Fatal("old snapshot accepted")
	}
	stamp("socks-telemetry.json", time.Now().Add(time.Second))
	if l.Observe(time.Now()).TelemetryFresh {
		t.Fatal("future snapshot accepted")
	}
	stamp("status", time.Now())
	if !l.Observe(time.Now()).TimeLimit {
		t.Fatal("session TIME_LIMIT ignored")
	}
	l.startTicks++
	if l.Observe(time.Now()).Alive {
		t.Fatal("PID reuse followed")
	}
	l.startTicks--
	l.Executable += "-other"
	if l.Observe(time.Now()).Alive {
		t.Fatal("foreign executable followed")
	}
	l.PID = 2147483647
	if l.Observe(time.Now()).Alive {
		t.Fatal("stale files masked a dead process")
	}
}

func TestPrivateInputAndProcStat(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "file")
	os.WriteFile(p, []byte("private"), 0600)
	if _, _, e := ReadPrivate(p); e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0644)
	if _, _, e := ReadPrivate(p); e == nil {
		t.Fatal("public input accepted")
	}
	os.Chmod(p, 0600)
	os.Symlink(p, filepath.Join(d, "link"))
	if _, _, e := ReadPrivate(filepath.Join(d, "link")); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Link(p, filepath.Join(d, "hard"))
	if _, _, e := ReadPrivate(p); e == nil {
		t.Fatal("hardlink accepted")
	}
	if _, _, e := processStart([]byte("broken")); e == nil {
		t.Fatal("invalid process identity accepted")
	}
}
