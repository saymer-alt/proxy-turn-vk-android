// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type qOptions struct {
	Input, Output, Auth, Device, Credentials, DNS string
	MaxWorkers                                    int
}

func qError(code string) error { return errors.New("WDTT_QWDTT_" + code) }
func qText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return true
}
func qNumber(s string, max int) (int, error) {
	if s == "" || len(s) > 5 || len(s) > 1 && s[0] == '0' {
		return 0, qError("NUMBER_INVALID")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, qError("NUMBER_INVALID")
		}
	}
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 || n > max {
		return 0, qError("NUMBER_INVALID")
	}
	return n, nil
}

// Descriptor-relative I/O pins each directory and never follows symlinks.
func qDir(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, qError("PRIVATE_DIRECTORY_REQUIRED")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, qError("PRIVATE_DIRECTORY_REQUIRED")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, qError("PRIVATE_DIRECTORY_REQUIRED")
		}
		fd = next
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0777 != 0700 || int(st.Uid) != os.Geteuid() {
		unix.Close(fd)
		return -1, qError("PRIVATE_DIRECTORY_REQUIRED")
	}
	return fd, nil
}
func qRead(path string) ([]byte, error) {
	dir, e := qDir(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer unix.Close(dir)
	fd, e := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, qError("PRIVATE_FILE_REQUIRED")
	}
	f := os.NewFile(uintptr(fd), "private")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size > 16384 || int(st.Uid) != os.Geteuid() {
		return nil, qError("PRIVATE_FILE_REQUIRED")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 {
		return nil, qError("PRIVATE_FILE_REQUIRED")
	}
	return b, nil
}
func qWrite(path string, data []byte) error {
	dir, e := qDir(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer unix.Close(dir)
	if filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return qError("OUTPUT_REJECTED")
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		return qError("OUTPUT_REJECTED")
	}
	tmp := ".qwdtt-" + hex.EncodeToString(random[:])
	fd, e := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return qError("OUTPUT_REJECTED")
	}
	defer unix.Unlinkat(dir, tmp, 0)
	f := os.NewFile(uintptr(fd), "private")
	if f.Chmod(0600) != nil {
		f.Close()
		return qError("OUTPUT_REJECTED")
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return qError("OUTPUT_REJECTED")
	}
	if unix.Linkat(dir, tmp, dir, filepath.Base(path), 0) != nil {
		return qError("OUTPUT_EXISTS_OR_REJECTED")
	}
	// A sync failure leaves a protected complete file, never an overwritten file.
	if unix.Unlinkat(dir, tmp, 0) != nil || unix.Fsync(dir) != nil {
		return qError("OUTPUT_SYNC_FAILED")
	}
	return nil
}
func qParse(raw []byte, o qOptions, availableKiB int64) (labConfig, string, error) {
	// A private text file may have one final line ending, never multiple lines.
	if len(raw) >= 2 && string(raw[len(raw)-2:]) == "\r\n" {
		raw = raw[:len(raw)-2]
	} else if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	c := labConfig{}
	reject := func(code string) (labConfig, string, error) { return c, "", qError(code) }
	if len(raw) == 0 || len(raw) > 8192 || !qText(string(raw), 8192) {
		return reject("URI_INVALID")
	}
	u, e := url.Parse(string(raw))
	if e != nil || u.Scheme != "qwdtt" || u.Host != "config" || u.User != nil || u.Path != "" || u.Fragment != "" || u.Opaque != "" {
		return reject("URI_INVALID")
	}
	values, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return reject("QUERY_INVALID")
	}
	allowed := map[string]bool{"name": true, "peer": true, "hashes": true, "workers": true, "port": true, "pass": true}
	for k, v := range values {
		if !allowed[k] || len(v) != 1 || v[0] == "" || !qText(v[0], 4096) {
			return reject("QUERY_INVALID")
		}
	}
	for _, k := range []string{"name", "peer", "hashes", "workers", "port", "pass"} {
		if len(values[k]) != 1 {
			return reject("FIELDS_REQUIRED")
		}
	}
	name := values.Get("name")
	if !qText(name, 128) || strings.TrimSpace(name) == "" {
		return reject("NAME_INVALID")
	}
	peer := values.Get("peer")
	host, port, e := net.SplitHostPort(peer)
	if e != nil || net.ParseIP(host) == nil || net.ParseIP(host).To4() == nil || strings.Contains(host, ":") {
		return reject("PEER_IPV4_REQUIRED")
	}
	if _, e = qNumber(port, 65535); e != nil {
		return reject("PEER_PORT_INVALID")
	}
	ip := net.ParseIP(host)
	if ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return reject("PEER_IPV4_REQUIRED")
	}
	local, e := qNumber(values.Get("port"), 65535)
	if e != nil {
		return reject("PORT_INVALID")
	}
	workers, e := qNumber(values.Get("workers"), 108)
	if e != nil {
		return reject("WORKERS_INVALID")
	}
	if o.Auth == "" {
		return reject("AUTH_REQUIRED")
	}
	if o.Device == "" {
		return reject("DEVICE_REQUIRED")
	}
	if o.MaxWorkers == 0 {
		return reject("DEVICE_WORKER_BUDGET_REQUIRED")
	}
	if !qText(o.Device, 128) || strings.Contains(o.Device, "|") {
		return reject("DEVICE_INVALID")
	}
	customDNS := strings.TrimPrefix(o.DNS, "custom:")
	validCustomDNS := strings.HasPrefix(o.DNS, "custom:") && net.ParseIP(customDNS) != nil && net.ParseIP(customDNS).To4() != nil
	if o.DNS != "yandex" && o.DNS != "doh-cloudflare" && o.DNS != "doh-google" && !validCustomDNS {
		return reject("DNS_CHOICE_REQUIRED")
	}
	hashes := strings.Split(values.Get("hashes"), ",")
	if len(hashes) == 0 || len(hashes) > workers {
		return reject("HASH_WORKER_BUDGET_EXCEEDED")
	}
	// The existing anonymous client launches 9 effective TURN sessions
	// from its historical -n 12 profile (one workersPerGroup=9 group).
	// A public qwdtt://workers=9 is admitted ONLY for a single hash,
	// explicitly authorized with max-workers=9 and >=128MiB available.
	// 16/18 and multiple hashes are NOT silently downscaled. Account
	// quota (<=4) and client protocol are completely unchanged.
	runtimeWorkers := workers
	switch o.Auth {
	case "account":
		if o.Credentials == "" {
			return reject("CREDENTIALS_REQUIRED")
		}
		if workers > 4 || o.MaxWorkers < 1 || o.MaxWorkers > 4 || workers > o.MaxWorkers {
			return reject("WORKER_BUDGET_EXCEEDED")
		}
		if availableKiB < 98304+int64(workers-1)*16384 {
			return reject("DEVICE_MEMORY_INSUFFICIENT")
		}
	case "anonymous":
		if workers != 9 || len(hashes) != 1 || o.MaxWorkers != 9 || o.Credentials != "" {
			return reject("ANONYMOUS_WORKER_POLICY_UNRESOLVED")
		}
		if availableKiB < 131072 {
			return reject("DEVICE_MEMORY_INSUFFICIENT")
		}
		runtimeWorkers = 12 // runtime's already field-tested effective=9.
	default:
		return reject("AUTH_INVALID")
	}
	seen := map[string]bool{}
	for i, h := range hashes {
		h = strings.TrimSpace(h)
		if h == "" || len(h) > 512 || seen[h] {
			return reject("HASH_INVALID")
		}
		for _, r := range h {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return reject("HASH_INVALID")
			}
		}
		seen[h] = true
		hashes[i] = h
	}
	pass := values.Get("pass")
	if len(pass) < 16 || len(pass) > 1024 || strings.Contains(pass, "|") {
		return reject("PASSWORD_INVALID")
	}
	c = labConfig{Peer: peer, Listen: fmt.Sprintf("127.0.0.1:%d", local), Password: pass, VK: strings.Join(hashes, ","), Auth: o.Auth, CredsFile: o.Credentials, DNS: o.DNS, Workers: runtimeWorkers, Device: o.Device}
	if labValidate(c) != nil {
		return reject("CLIENT_POLICY_REJECTED")
	}
	return c, name, nil
}
func qMemory() int64 {
	b, e := os.ReadFile("/proc/meminfo")
	if e != nil {
		return 0
	}
	var free int64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		n, e := strconv.ParseInt(f[1], 10, 64)
		if e != nil || n < 0 {
			continue
		}
		if f[0] == "MemAvailable:" {
			return n
		}
		if f[0] == "MemFree:" {
			free = n
		}
	}
	return free
}
func qImport(o qOptions) error {
	if o.Input == "" || o.Output == "" {
		return qError("PRIVATE_INPUT_AND_OUTPUT_REQUIRED")
	}
	raw, e := qRead(o.Input)
	if e != nil {
		return e
	}
	c, name, e := qParse(raw, o, qMemory())
	if e != nil {
		return e
	}
	if c.Auth == "account" {
		creds, e := qRead(c.CredsFile)
		if e != nil {
			return qError("PRIVATE_CREDENTIALS_REQUIRED")
		}
		var cf vkCredsFile
		if json.Unmarshal(creds, &cf) != nil {
			return qError("CREDENTIALS_INVALID")
		}
		for _, h := range ParseHashes(c.VK) {
			v, ok := cf.Hashes[h]
			if !ok || v.User == "" || v.Pass == "" || len(turnURLsToAddresses(v.URLs)) == 0 {
				return qError("CREDENTIALS_MISSING_HASH")
			}
		}
	}
	addr, e := net.ResolveUDPAddr("udp4", c.Listen)
	if e != nil {
		return qError("PORT_INVALID")
	}
	sock, e := net.ListenUDP("udp4", addr)
	if e != nil {
		if errors.Is(e, unix.EADDRINUSE) {
			return qError("PORT_OCCUPIED")
		}
		return qError("PORT_UNAVAILABLE")
	}
	sock.Close()
	data, e := json.Marshal(c)
	if e != nil {
		return qError("OUTPUT_REJECTED")
	}
	var obj map[string]interface{}
	json.Unmarshal(data, &obj)
	obj["name"] = name
	if c.Auth == "anonymous" {
		obj["qwdtt_requested_workers"] = 9
		obj["qwdtt_effective_workers"] = 9
	}
	data, e = json.MarshalIndent(obj, "", "  ")
	if e != nil {
		return qError("OUTPUT_REJECTED")
	}
	return qWrite(o.Output, append(data, '\n'))
}
func qImportCLI(args []string, out, errOut io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(out, "qWDTT offline import: -uri-file PRIVATE0600 -output-file NEW_PRIVATE0600 -auth account -credentials-file PRIVATE0600 -max-workers 1..4 OR -auth anonymous -max-workers 9 (single hash); -device EXPLICIT_ID -dns EXPLICIT_CHOICE; parent directories0700; no secret argv, no connection")
		return 0
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		fmt.Fprintln(errOut, "WDTT_QWDTT_PRIVATE_PROCESS_REQUIRED")
		return 78
	}
	var o qOptions
	f := flag.NewFlagSet("qwdtt-import", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.Input, "uri-file", "", "")
	f.StringVar(&o.Output, "output-file", "", "")
	f.StringVar(&o.Auth, "auth", "", "")
	f.StringVar(&o.Device, "device", "", "")
	f.StringVar(&o.Credentials, "credentials-file", "", "")
	f.StringVar(&o.DNS, "dns", "", "")
	f.IntVar(&o.MaxWorkers, "max-workers", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 {
		fmt.Fprintln(errOut, "WDTT_QWDTT_OPTIONS_INVALID")
		return 78
	}
	if e := qImport(o); e != nil {
		fmt.Fprintln(errOut, e.Error())
		return 78
	}
	fmt.Fprintln(out, "WDTT_QWDTT_PRIVATE_CONFIG_CREATED")
	return 0
}
