// SPDX-License-Identifier: GPL-3.0-or-later
package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketInodeMustBelongToObservedProcess(t *testing.T) {
	d := t.TempDir()
	os.Mkdir(filepath.Join(d, "net"), 0700)
	os.Mkdir(filepath.Join(d, "fd"), 0700)
	table := filepath.Join(d, "net/tcp")
	row := "0: 0100007F:0439 00000000:0000 0A 0:0 0:0 0 0 0 4711\n"
	os.WriteFile(table, []byte(row), 0600)
	if ownsSocks(d) {
		t.Fatal("foreign socket accepted")
	}
	link := filepath.Join(d, "fd/7")
	os.Symlink("socket:[4711]", link)
	if !ownsSocks(d) {
		t.Fatal("matching socket ignored")
	}
	os.Remove(link)
	os.Symlink("socket:[4712]", link)
	if ownsSocks(d) {
		t.Fatal("wrong socket inode accepted")
	}
	now := time.Now()
	m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation { return Observation{Alive: true, Verified: true, TelemetryFresh: true} }, Probe: func(context.Context) string { t.Fatal("foreign SOCKS probed"); return "FRESH_RESPONSE" }}
	for i := 0; i < 3; i++ {
		m.Check(context.Background())
	}
	if m.result.State != "DEGRADED" || m.result.Reason != "SOCKS_UNAVAILABLE_OR_FOREIGN" {
		t.Fatal(m.result)
	}
}
