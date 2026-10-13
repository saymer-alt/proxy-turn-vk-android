// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplicitPrivateConfigAndRedactedErrors(t *testing.T) {
	oldArgs, oldStderr := os.Args, os.Stderr
	defer func() { os.Args, os.Stderr = oldArgs, oldStderr }()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d, "health.json")
	for _, body := range []string{`{}`, `{"pid":1,"target_url":"https://SECRET_CANARY@owner.invalid","interval_seconds":10}`, `{"unknown":"SECRET_CANARY"}`, `{} {}`} {
		os.WriteFile(path, []byte(body), 0600)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = w
		os.Args = []string{"wdtt-health", "-config-file", path}
		code := run()
		w.Close()
		b, _ := io.ReadAll(r)
		r.Close()
		os.Stderr = oldStderr
		if code != 78 || strings.Contains(string(b), "SECRET_CANARY") || !strings.Contains(string(b), "HEALTH_CONFIG_INVALID_EXPLICIT_TARGET_AND_INTERVAL_REQUIRED") {
			t.Fatal("missing context accepted or leaked")
		}
	}
}
