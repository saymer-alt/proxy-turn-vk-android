// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/turn/v5"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in local-only harness, with real upstream WRAP/DTLS/GETCONF handler.
// main, TUN, OS routes/firewall/sysctl, Telegram, HTTP control API never run.
func TestLocalPairHarness(t *testing.T) {
	dir := os.Getenv("WDTT_LOCAL_PAIR_DIR")
	if dir == "" {
		t.Skip("local harness disabled")
	}
	log.SetOutput(io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, clientPub, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	password := "SYNTHETIC-LOCAL-WDTT-PASSWORD-ONLY"
	db = &Database{Devices: map[string]*ClientDevice{"fixture": {DeviceID: "fixture", IP: "10.66.66.2", PrivKey: clientPriv, PubKey: clientPub}}, Passwords: map[string]*PasswordEntry{password: {DeviceID: "fixture", DeviceIDs: []string{"fixture"}, MaxDevices: 1, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}}}
	dbFile = filepath.Join(dir, "server-db.json")
	dns = "10.66.66.1"
	if err = serverWrapKeys.SetPasswords("", []string{password}); err != nil {
		t.Fatal(err)
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.66.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	privHex, _ := b64ToHex(serverPriv)
	pubHex, _ := b64ToHex(clientPub)
	if err = dev.IpcSet("private_key=" + privHex + "\nlisten_port=19001\npublic_key=" + pubHex + "\nallowed_ip=10.66.66.2/32\n"); err != nil {
		t.Fatal(err)
	}
	if err = dev.Up(); err != nil {
		t.Fatal(err)
	}
	tcp, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.66.66.1"), Port: 18080})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("WDTT-LOCAL-TCP-OK\n")) })}
	defer httpServer.Close()
	go httpServer.Serve(tcp)
	echo, err := tnet.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.66.66.1"), Port: 18081})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := echo.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = echo.WriteTo(b[:n], a)
		}
	}()
	dnsUDP, err := tnet.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.66.66.1"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsUDP.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := dnsUDP.ReadFrom(b)
			if e != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b[:n]) != nil {
				continue
			}
			m.Header.Response = true
			m.Header.RecursionAvailable = true
			for _, q := range m.Questions {
				if q.Type == dnsmessage.TypeA {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{10, 66, 66, 1}}})
				}
			}
			out, e := m.Pack()
			if e == nil {
				_, _ = dnsUDP.WriteTo(out, a)
			}
		}
	}()
	// TURN and every relay socket bind exclusively to loopback.
	turnSock, err := net.ListenPacket("udp4", "127.0.0.1:19002")
	if err != nil {
		t.Fatal(err)
	}
	defer turnSock.Close()
	turnServer, err := turn.NewServer(turn.ServerConfig{Realm: "wdtt-local", AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
		if a.Username != "fixture" && !(os.Getenv("WDTT_QWDTT_CLIENT") != "" && a.Username == "fixture2") {
			return "", nil, false
		}
		if a.Username == "fixture2" {
			_ = os.WriteFile(filepath.Join(dir, "qwdtt-second-hash-turn"), []byte("SECOND_HASH_AUTH_REQUESTED\n"), 0600)
		}
		return a.Username, turn.GenerateAuthKey(a.Username, a.Realm, "SYNTHETIC-TURN-PASSWORD"), true
	}, PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: turnSock, PermissionHandler: func(_ net.Addr, ip net.IP) bool { return ip.IsLoopback() }, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer turnServer.Close()
	if relay := os.Getenv("WDTT_HARDENED_RELAY_BIN"); relay != "" {
		data, _ := json.Marshal(db)
		if os.WriteFile(dbFile, data, 0600) != nil {
			t.Fatal("db write")
		}
		cfg, _ := json.Marshal(map[string]string{"listen": "127.0.0.1:19003", "wg_endpoint": "127.0.0.1:19001", "server_public_key": serverPub, "dns": dns, "database_file": dbFile})
		path := filepath.Join(dir, "server-config.json")
		if os.WriteFile(path, cfg, 0600) != nil {
			t.Fatal("server config write")
		}
		cmd := exec.Command(relay, "-config-file", path)
		// The Python runner may terminate this harness before Go defers run.
		// Never leave its relay behind to consume the next fixture's endpoint.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if cmd.Start() != nil {
			t.Fatal("relay start")
		}
		defer func() {
			cmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-done
			}
		}()
	} else {
		cert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := listenWrapped(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19003}, serverWrapKeys)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := dtls.NewListenerWithOptions(wrap, dtls.WithCertificates(cert), dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret), dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)), dtls.WithMTU(1100))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		keys := &wgKeys{serverPrivate: serverPriv, serverPublic: serverPub, clientPrivate: clientPriv, clientPublic: clientPub}
		go func() {
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); handleConn(ctx, c, "127.0.0.1:19001", dev, keys) }()
			}
		}()
	}
	creds := map[string]any{"hashes": map[string]any{"fixture": map[string]any{"u": "fixture", "p": "SYNTHETIC-TURN-PASSWORD", "urls": []string{"turn:127.0.0.1:19002?transport=udp"}}}}
	if os.Getenv("WDTT_QWDTT_CLIENT") != "" {
		creds["hashes"].(map[string]any)["fixture2"] = map[string]any{"u": "fixture2", "p": "SYNTHETIC-TURN-PASSWORD", "urls": []string{"turn:127.0.0.1:19002?transport=udp"}}
	}
	cbytes, _ := json.Marshal(creds)
	if os.WriteFile(filepath.Join(dir, "turn-creds.json"), cbytes, 0600) != nil {
		t.Fatal("creds write")
	}
	config := map[string]any{"peer": "127.0.0.1:19003", "listen": "127.0.0.1:19000", "password": password, "vk": "fixture", "auth": "account", "creds_file": filepath.Join(dir, "turn-creds.json"), "dns": "custom:127.0.0.1", "workers": 1, "device": "fixture"}
	cfg, _ := json.Marshal(config)
	if client := os.Getenv("WDTT_QWDTT_CLIENT"); client != "" {
		uri := "qwdtt://config?" + url.Values{"name": {"Synthetic pair"}, "peer": {"127.0.0.1:19003"}, "hashes": {"fixture,fixture2"}, "workers": {"2"}, "port": {"19000"}, "pass": {password}}.Encode()
		input := filepath.Join(dir, "profile.uri")
		if os.WriteFile(input, []byte(uri), 0600) != nil {
			t.Fatal("private URI write")
		}
		cmd := exec.Command(client, "-import-qwdtt", "-uri-file", input, "-output-file", filepath.Join(dir, "client.json"), "-auth", "account", "-device", "fixture", "-credentials-file", filepath.Join(dir, "turn-creds.json"), "-dns", "custom:127.0.0.1", "-max-workers", "2")
		if err := cmd.Run(); err != nil {
			t.Fatal("private import rejected")
		}
	} else if os.WriteFile(filepath.Join(dir, "client.json"), cfg, 0600) != nil {
		t.Fatal("config write")
	}
	if os.WriteFile(filepath.Join(dir, "READY"), []byte("LOCAL-ONLY\n"), 0600) != nil {
		t.Fatal("ready write")
	}
	// Persist only numeric WG metrics, never IPC keys or raw configuration.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	limit := time.After(3 * time.Minute)
	for {
		select {
		case <-limit:
			return
		case <-ticker.C:
			status, _ := dev.IpcGet()
			metrics := map[string]string{}
			for _, line := range strings.Split(status, "\n") {
				pair := strings.SplitN(line, "=", 2)
				if len(pair) == 2 && (pair[0] == "rx_bytes" || pair[0] == "tx_bytes" || strings.HasPrefix(pair[0], "last_handshake_time_")) {
					metrics[pair[0]] = pair[1]
				}
			}
			m, _ := json.Marshal(metrics)
			_ = os.WriteFile(filepath.Join(dir, "wg-metrics.json"), m, 0600)
			if _, e := os.Stat(filepath.Join(dir, "STOP")); e == nil {
				return
			}
		}
	}
}
