// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"encoding/json"
	"golang.org/x/sys/unix"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const qCanary = "SYNTHETIC_QWDTT_PASSWORD_123"

func qURI(workers, hashes string) string {
	return "qwdtt://config?" + url.Values{"name": {"Synthetic"}, "peer": {"192.0.2.1:56000"}, "hashes": {hashes}, "workers": {workers}, "port": {"19000"}, "pass": {qCanary}}.Encode()
}
func qTestOptions() qOptions {
	return qOptions{Auth: "account", Device: "synthetic-device", Credentials: "/private/creds.json", DNS: "yandex", MaxWorkers: 4}
}
func TestQwdttParse(t *testing.T) {
	c, name, e := qParse([]byte(qURI("4", "hash_a,hash_b")), qTestOptions(), 200000)
	if e != nil || name != "Synthetic" || c.VK != "hash_a,hash_b" || c.Workers != 4 || labValidate(c) != nil {
		t.Fatal("valid multi-hash import rejected")
	}
	for _, w := range []string{"0", "5", "9", "16", "18", "109", "-1", "+1", "01", "1.0", "999999"} {
		if _, _, e = qParse([]byte(qURI(w, "hash_a")), qTestOptions(), 200000); e == nil {
			t.Fatal("invalid workers accepted")
		}
	}
	invalid := []string{qURI("1", "a,b"), qURI("2", "a,a"), qURI("1", "a,,b"), qURI("1", "https://example.invalid/hash"), qURI("1", "a") + "&pass=other", qURI("1", "a") + "&unknown=x", qURI("1", "a") + "#x", strings.Replace(qURI("1", "a"), "qwdtt://config?", "https://config?", 1), qURI("1", "a") + "&name=%0a", qURI("1", "a") + "&name=%ZZ", strings.Repeat("x", 8193)}
	for _, uri := range invalid {
		_, _, e = qParse([]byte(uri), qTestOptions(), 200000)
		if e == nil || strings.Contains(e.Error(), qCanary) {
			t.Fatal("unsafe URI admission/error")
		}
	}
	for _, k := range []string{"peer", "port", "pass", "name", "hashes", "workers"} {
		u, _ := url.Parse(qURI("1", "a"))
		v := u.Query()
		v.Del(k)
		u.RawQuery = v.Encode()
		if _, _, e = qParse([]byte(u.String()), qTestOptions(), 200000); e == nil {
			t.Fatal("missing field accepted")
		}
	}
	for _, pair := range [][2]string{{"port", "0"}, {"port", "65536"}, {"peer", "host.invalid:56000"}, {"peer", "[::1]:56000"}, {"peer", "0.0.0.0:56000"}, {"peer", "192.0.2.1:0"}, {"pass", "short"}, {"pass", qCanary + "|x"}, {"hashes", "a%252Cb"}} {
		u, _ := url.Parse(qURI("1", "a"))
		v := u.Query()
		v.Set(pair[0], pair[1])
		u.RawQuery = v.Encode()
		if _, _, e = qParse([]byte(u.String()), qTestOptions(), 200000); e == nil {
			t.Fatal("invalid field accepted")
		}
	}
	for _, change := range []func(*qOptions){func(o *qOptions) { o.Auth = "" }, func(o *qOptions) { o.Device = "" }, func(o *qOptions) { o.Credentials = "" }, func(o *qOptions) { o.MaxWorkers = 0 }, func(o *qOptions) { o.MaxWorkers = 1 }, func(o *qOptions) { o.Auth = "anonymous" }, func(o *qOptions) { o.Device = "bad|device" }, func(o *qOptions) { o.DNS = "" }} {
		o := qTestOptions()
		change(&o)
		if _, _, e = qParse([]byte(qURI("2", "a,b")), o, 200000); e == nil {
			t.Fatal("missing/invalid explicit context accepted")
		}
	}
	if _, _, e = qParse([]byte(qURI("4", "a")), qTestOptions(), 147455); e == nil {
		t.Fatal("RAM budget ignored")
	}
	if _, _, e = qParse([]byte(qURI("4", "a")), qTestOptions(), 147456); e != nil {
		t.Fatal("RAM boundary rejected")
	}
}
func TestAccountHashBudget(t *testing.T) {
	for workers := 1; workers <= 4; workers++ {
		for hashes := 1; hashes <= workers; hashes++ {
			sum := 0
			for g := 0; g < hashes; g++ {
				start, end := accountGroupRange(g, hashes, workers)
				if start != sum || end <= start {
					t.Fatal("invalid distribution")
				}
				sum = end
			}
			if sum != workers {
				t.Fatal("worker budget multiplied")
			}
		}
	}
}
func qPrivate(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	p := filepath.Join(dir, name)
	if os.WriteFile(p, data, 0600) != nil {
		t.Fatal("fixture write")
	}
	return p
}
func TestQwdttPrivateLifecycle(t *testing.T) {
	listener, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal("fixture bind")
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	u, _ := url.Parse(qURI("2", "a,b"))
	v := u.Query()
	v.Set("port", fmtInt(port))
	u.RawQuery = v.Encode()
	input := qPrivate(t, "uri", []byte(u.String()))
	creds := qPrivate(t, "creds", []byte(`{"hashes":{"a":{"u":"synthetic","p":"synthetic","urls":["turn:127.0.0.1:3478"]},"b":{"u":"synthetic","p":"synthetic","urls":["turn:127.0.0.1:3478"]}}}`))
	o := qTestOptions()
	o.Input = input
	o.Output = filepath.Join(filepath.Dir(input), "config.json")
	o.Credentials = creds
	if e = qImport(o); e == nil || e.Error() != "WDTT_QWDTT_PORT_OCCUPIED" {
		t.Fatal("occupied port admitted")
	}
	listener.Close()
	if e = qImport(o); e != nil {
		t.Fatal("private import failed")
	}
	before, _ := os.ReadFile(o.Output)
	var c labConfig
	if json.Unmarshal(before, &c) != nil || c.Password != qCanary || c.VK != "a,b" || labValidate(c) != nil {
		t.Fatal("config not usable by client")
	}
	st, _ := os.Stat(o.Output)
	if st.Mode().Perm() != 0600 {
		t.Fatal("open config permissions")
	}
	if qImport(o) == nil {
		t.Fatal("overwrite accepted")
	}
	after, _ := os.ReadFile(o.Output)
	if !bytes.Equal(before, after) {
		t.Fatal("existing config modified")
	}
	for _, mode := range []os.FileMode{0644, 0400, 0666} {
		os.Chmod(input, mode)
		if qImport(o) == nil {
			t.Fatal("unsafe input mode admitted")
		}
	}
	os.Chmod(input, 0600)
	alias := filepath.Join(filepath.Dir(input), "alias")
	os.Symlink(input, alias)
	o.Input = alias
	if qImport(o) == nil {
		t.Fatal("symlink input admitted")
	}
	o.Input = input
	hard := filepath.Join(filepath.Dir(input), "hard")
	os.Link(input, hard)
	if qImport(o) == nil {
		t.Fatal("hardlink input admitted")
	}
	os.Remove(hard)
	os.Chmod(filepath.Dir(input), 0755)
	if qImport(o) == nil {
		t.Fatal("open directory admitted")
	}
	os.Chmod(filepath.Dir(input), 0700)
	missing := qPrivate(t, "missing", []byte(`{"hashes":{}}`))
	o.Credentials = missing
	if qImport(o) == nil {
		t.Fatal("missing credentials admitted")
	}
	var stdout, stderr bytes.Buffer
	if qImportCLI([]string{"-uri-file", input, "-output-file", filepath.Join(filepath.Dir(input), "second.json"), "-auth", "account", "-device", "synthetic-device", "-credentials-file", creds, "-dns", "yandex", "-max-workers", "2"}, &stdout, &stderr) != 0 || strings.Contains(stdout.String()+stderr.String(), qCanary) {
		t.Fatal("CLI private import failed or leaked")
	}
	stdout.Reset()
	stderr.Reset()
	if qImportCLI([]string{"-pass", qCanary}, &stdout, &stderr) != 78 || strings.Contains(stdout.String()+stderr.String(), qCanary) {
		t.Fatal("argv secret leaked")
	}
}

func FuzzQwdttParse(f *testing.F) {
	f.Add(qURI("1", "synthetic"))
	f.Add("qwdtt://config?pass=synthetic")
	f.Fuzz(func(t *testing.T, raw string) {
		c, _, e := qParse([]byte(raw), qTestOptions(), 200000)
		if e != nil && !strings.HasPrefix(e.Error(), "WDTT_QWDTT_") {
			t.Fatal("unredacted parser error")
		}
		if e == nil && labValidate(c) != nil {
			t.Fatal("imported config violates runtime policy")
		}
	})
}

func TestQwdttAtomicAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	target := filepath.Join(dir, "kept")
	os.WriteFile(target, []byte("KEEP"), 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	for _, path := range []string{target, link} {
		if qWrite(path, []byte(qCanary)) == nil {
			t.Fatal("existing file/link overwritten")
		}
	}
	b, _ := os.ReadFile(target)
	if string(b) != "KEEP" {
		t.Fatal("foreign data changed")
	}
	fifo := filepath.Join(dir, "fifo")
	if unix.Mkfifo(fifo, 0600) != nil {
		t.Fatal("fixture FIFO")
	}
	if _, e := qRead(fifo); e == nil {
		t.Fatal("FIFO accepted")
	}
	parentLink := filepath.Join(t.TempDir(), "parent")
	os.Symlink(dir, parentLink)
	if _, e := qRead(filepath.Join(parentLink, "kept")); e == nil {
		t.Fatal("symlink directory accepted")
	}
	old := unix.Umask(0777)
	defer unix.Umask(old)
	output := filepath.Join(dir, "strict-umask.json")
	if qWrite(output, []byte("{}")) != nil {
		t.Fatal("private writer under strict umask")
	}
	st, _ := os.Stat(output)
	if st.Mode().Perm() != 0600 {
		t.Fatal("output not exactly private0600")
	}
	staged, _ := filepath.Glob(filepath.Join(dir, ".qwdtt-*"))
	if len(staged) != 0 {
		t.Fatal("staging files leaked")
	}
}
func fmtInt(n int) string { return strconv.Itoa(n) }
