// SPDX-License-Identifier: GPL-3.0-or-later
// Narrow laboratory entry point. Upstream diagnostics are deliberately disabled:
// HTTP errors, captcha protocol, panic output and vendor loggers are untrusted.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type labConfig struct {
	Peer      string `json:"peer"`
	Listen    string `json:"listen"`
	Password  string `json:"password"`
	VK        string `json:"vk"`
	Auth      string `json:"auth"`
	CredsFile string `json:"creds_file"`
	DNS       string `json:"dns"`
	Workers   int    `json:"workers"`
	Device    string `json:"device"`
	Mode      string `json:"mode"`
	SocksListen string `json:"socks_listen"`
}

var labCfg labConfig
var labDir string
var labErr = errors.New("private laboratory file rejected")

func labPrivateDir(dir string) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != filepath.Clean(dir) || !filepath.IsAbs(dir) {
		return labErr
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return labErr
	}
	// Use descriptor metadata for the actual file, not ls output.
	var u unix.Stat_t
	if unix.Lstat(dir, &u) != nil || int(u.Uid) != os.Geteuid() {
		return labErr
	}
	return nil
}
func labRead(path string) ([]byte, error) {
	if labPrivateDir(filepath.Dir(path)) != nil {
		return nil, labErr
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, labErr
	}
	f := os.NewFile(uintptr(fd), "private")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || st.Size > 65536 {
		return nil, labErr
	}
	return io.ReadAll(io.LimitReader(f, 65537))
}
func labWrite(name string, data []byte) error {
	if labPrivateDir(labDir) != nil {
		return labErr
	}
	dst := filepath.Join(labDir, name)
	if _, err := os.Lstat(dst); err == nil {
		if _, err = labRead(dst); err != nil {
			return labErr
		}
	} else if !os.IsNotExist(err) {
		return labErr
	}
	f, err := os.CreateTemp(labDir, ".wdtt-stage-")
	if err != nil {
		return labErr
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return labErr
	}
	if os.Rename(tmp, dst) != nil {
		return labErr
	}
	return nil
}
func labStatus(code string) {
	// Callers supply compile-time fixed codes, never upstream error strings.
	_ = labWrite("status", []byte(code+"\n"))
}


// GETCONF uses its own status file because any already-established DTLS worker
// may be registered while a different worker awaits its 45-second reply.
// Never record server-supplied text, keys, passwords or arbitrary error strings.
var labGetConfMu sync.Mutex
var labGetConfFinal bool

func labGetConfStatus(code string) {
	switch code {
	case "NOT_REQUESTED", "GETCONF_REQUESTED", "GETCONF_NO_CONFIG",
		"GETCONF_TIMEOUT", "GETCONF_DENIED", "GETCONF_ERROR",
		"GETCONF_RECEIVED", "CONFIG_READY":
	default:
		return
	}
	labGetConfMu.Lock()
	defer labGetConfMu.Unlock()
	if labGetConfFinal && code != "NOT_REQUESTED" {
		return
	}
	if code == "NOT_REQUESTED" {
		labGetConfFinal = false
	}
	if code == "CONFIG_READY" {
		labGetConfFinal = true
	}
	if labWrite("getconf-status", []byte(code+"\n")) != nil {
		labStatus("CONFIG_WRITE_FAILED")
		os.Exit(78)
	}
}

// SOCKS status is separate from the GETCONF and TURN/DTLS results; a TCP
// listener alone is not evidence of a WireGuard handshake or routed traffic.
func labSocksStatus(code string) {
	if labCfg.Mode != "socks" {
		return
	}
	switch code {
	case "WAITING_FOR_WG", "WG_STARTING", "WG_CONFIG_REJECTED",
		"WG_START_FAILED", "SOCKS_BIND_FAILED", "SOCKS_LISTENING",
		"SOCKS_SERVER_FAILED", "SOCKS_STOPPED":
	default:
		return
	}
	if labWrite("socks-status", []byte(code+"\n")) != nil {
		labStatus("CONFIG_WRITE_FAILED")
		os.Exit(78)
	}
}

// For the experimental SOCKS profile, the server-provided WG endpoint must
// loop back into THIS WDTT client, not unexpectedly dial an external socket.
func labValidateSocksWG(c *wgQuickConfig) bool {
	if c == nil || c.endpoint != labCfg.Listen ||
		len(c.addresses) != 1 || len(c.dns) == 0 ||
		c.mtu < 576 || c.mtu > 1420 {
		return false
	}
	if !c.addresses[0].Is4() {
		return false
	}
	for _, d := range c.dns {
		if !d.Is4() {
			return false
		}
	}
	for _, raw := range c.allowedIPs {
		net, err := netip.ParsePrefix(raw)
		if err != nil || !net.Addr().Is4() {
			return false
		}
	}
	return true
}

func labGetConfResult(conf string, err error) string {
	if err != nil {
		if strings.HasPrefix(err.Error(), "FATAL_AUTH:") {
			return "GETCONF_DENIED"
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return "GETCONF_TIMEOUT"
		}
		return "GETCONF_ERROR"
	}
	if conf == "" {
		return "GETCONF_NO_CONFIG"
	}
	return "GETCONF_RECEIVED"
}
func labApplyFlags() {
	mode := labCfg.Mode
	if mode == "" {
		mode = "vpn"
	}
	values := map[string]string{"peer": labCfg.Peer, "listen": labCfg.Listen, "password": labCfg.Password, "vk": labCfg.VK, "vk-auth": labCfg.Auth, "vk-creds-file": labCfg.CredsFile, "go-dns": labCfg.DNS, "device-id": labCfg.Device, "n": fmt.Sprint(labCfg.Workers), "mode": mode}
	if mode == "socks" {
		values["socks"] = labCfg.SocksListen
	}
	for k, v := range values {
		if flag.Set(k, v) != nil {
			os.Exit(78)
		}
	}
}
func labValidate(c labConfig) error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || host != "127.0.0.1" || port == "0" {
		return labErr
	}
	if _, err = net.ResolveUDPAddr("udp4", c.Listen); err != nil {
		return labErr
	}
	// First PoC uses literal IPv4 for the outer peer: no DNS/bootstrap ambiguity.
	h, _, err := net.SplitHostPort(c.Peer)
	if err != nil || net.ParseIP(h).To4() == nil || net.ParseIP(h).IsLoopback() == false && net.ParseIP(h).IsUnspecified() {
		return labErr
	}
	if len(c.Password) < 16 || c.VK == "" || strings.ContainsAny(c.Password, "|\r\n") || strings.ContainsAny(c.Device, "|\r\n") {
		return labErr
	}
	if c.Auth != "account" && c.Auth != "anonymous" {
		return labErr
	}
	switch c.Mode {
	case "", "vpn":
		if c.SocksListen != "" {
			return labErr
		}
	case "socks":
		// Local owner-only TCP SOCKS5; no LAN exposure or arbitrary listener.
		if c.SocksListen != "127.0.0.1:1081" {
			return labErr
		}
	default:
		return labErr
	}
	if c.Auth == "account" && (c.Workers < 1 || c.Workers > 4) {
		return labErr
	}
	if c.Auth == "anonymous" && c.Workers != 12 {
		return labErr
	}
	if c.Auth == "account" && c.CredsFile == "" {
		return labErr
	}
	return nil
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "-import-qwdtt" {
		os.Exit(qImportCLI(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("wt-client owner laboratory profile: -config-file /absolute/private/config.json; mode vpn or loopback-only socks (127.0.0.1:1081); no AWG daemon; secrets via 0600 file in 0700 directory; maximum session 30 minutes")
		return
	}
	if len(os.Args) != 3 || os.Args[1] != "-config-file" {
		fmt.Fprintln(os.Stderr, "WDTT_LAB_CONFIG_REQUIRED")
		os.Exit(78)
	}
	raw, err := labRead(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "WDTT_LAB_PRIVATE_FILE_REJECTED")
		os.Exit(78)
	}
	if json.Unmarshal(raw, &labCfg) != nil || labValidate(labCfg) != nil {
		fmt.Fprintln(os.Stderr, "WDTT_LAB_CONFIG_INVALID")
		os.Exit(78)
	}
	if labCfg.CredsFile != "" {
		if _, err = labRead(labCfg.CredsFile); err != nil {
			fmt.Fprintln(os.Stderr, "WDTT_LAB_CREDS_REJECTED")
			os.Exit(78)
		}
	}
	labDir = filepath.Dir(os.Args[2])
	if os.Chdir(labDir) != nil {
		os.Exit(78)
	}
	unix.Umask(0077)
	if labSilence() != nil {
		os.Exit(78)
	}
	os.Args = os.Args[:1]
	labStatus("STARTING")
	labGetConfStatus("NOT_REQUESTED")
	if labCfg.Mode == "socks" {
		labSocksStatus("WAITING_FOR_WG")
	}
	if labWrite("transport-ready", []byte("STARTING\n")) != nil {
		os.Exit(78)
	}
	go func() { time.Sleep(30 * time.Minute); labStatus("TIME_LIMIT"); os.Exit(75) }()
	upstreamMain()
	labStatus("STOPPED")
}
func labWorkerRegistered() {
	if labWrite("transport-ready", []byte("WORKER_REGISTERED\n")) != nil {
		labStatus("CONFIG_WRITE_FAILED")
		os.Exit(78)
	}
}
func labSilence() error {
	// No substring redactor can safely recognize every server-controlled secret.
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		return labErr
	}
	sink, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return labErr
	}
	defer sink.Close()
	if unix.Dup2(int(sink.Fd()), 1) != nil || unix.Dup2(int(sink.Fd()), 2) != nil || unix.Dup2(int(sink.Fd()), 0) != nil {
		return labErr
	}
	log.SetOutput(io.Discard)
	return nil
}
