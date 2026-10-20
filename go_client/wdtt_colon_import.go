// SPDX-License-Identifier: GPL-3.0-or-later
package main

// Private offline owner-lab import of the legacy, colon-separated WDTT link:
//
//   wdtt://IPv4:dtls_port:wg_port:local_port:password:hash[,hash2][#name]
//
// This is a DIFFERENT format from wdtt://base64(JSON) produced by certain
// modern panels. Never guess a decoding dialect, drop a password silently,
// treat encoded RtpTun keys as a WDTT password, or contact real servers here.
//
// The link does not state worker count, auth mode or device identity. They
// MUST be explicitly supplied via the existing private importer options.
// The inner WG port is checked but unused: it is supplied via GETCONF; the
// client's outer peer is IPv4:dtls_port. The owner-lab mode is loopback SOCKS.
//
// Successful parsing proves only a secure local configuration was created,
// not VK TURN credentials, live workers or TCP/UDP egress.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func wdttColonParse(raw []byte, o qOptions, availableKiB int64) (labConfig, string, error) {
	var empty labConfig
	fail := func(code string) (labConfig, string, error) {
		return empty, "", errors.New("WDTT_COLON_"+code)
	}
	if len(raw) >= 2 && string(raw[len(raw)-2:]) == "\r\n" {
		raw = raw[:len(raw)-2]
	} else if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 || len(raw) > 8192 || !qText(string(raw), 8192) {
		return fail("URI_INVALID")
	}
	s := string(raw)
	if !strings.HasPrefix(s, "wdtt://") {
		return fail("SCHEME_INVALID")
	}
	body := strings.TrimPrefix(s, "wdtt://")
	// URI query options do not exist in the colon dialect. A '#' suffix is
	// a display label only; '%' decoding is restricted to that suffix.
	if strings.Contains(body, "?") || strings.Count(body, "#") > 1 {
		return fail("FORMAT_INVALID")
	}
	name := "WDTT"
	if i := strings.IndexByte(body, '#'); i >= 0 {
		decoded, err := url.PathUnescape(body[i+1:])
		if err != nil || decoded == "" || !qText(decoded, 128) ||
			strings.TrimSpace(decoded) == "" {
			return fail("NAME_INVALID")
		}
		name = decoded
		body = body[:i]
	}
	// Exactly six fields; no implicit changes to passwords containing ':'.
	// Such ambiguous links must be handled by a separately reviewed dialect.
	parts := strings.Split(body, ":")
	if len(parts) != 6 {
		return fail("FIELDS_INVALID")
	}
	host := parts[0]
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return fail("PEER_IPV4_REQUIRED")
	}
	dtlsPort, err := qNumber(parts[1], 65535)
	if err != nil {
		return fail("DTLS_PORT_INVALID")
	}
	if _, err = qNumber(parts[2], 65535); err != nil {
		return fail("WG_PORT_INVALID")
	}
	localPort, err := qNumber(parts[3], 65535)
	if err != nil {
		return fail("LOCAL_PORT_INVALID")
	}
	// This initial colon implementation is owner-lab anonymous only.
	// Do not infer VK account credentials from a share link.
	if o.Auth != "anonymous" {
		return fail("ANONYMOUS_ONLY")
	}
	// No silent default. Classic clients commonly choose 16, but a public
	// link carries NO worker count. Require explicit operator decision.
	if o.MaxWorkers == 0 {
		return fail("WORKERS_REQUIRED")
	}
	for _, v := range parts[4:] {
		if v == "" || !qText(v, 4096) {
			return fail("CREDENTIAL_FIELD_INVALID")
		}
	}
	if strings.EqualFold(parts[5], "VK_HASH") {
		return fail("HASH_PLACEHOLDER_UNRESOLVED")
	}

	// Canonical qWDTT admission is reused as-is: exact worker group plans,
	// private keys, duplicate-hash rejection, memory floor, explicit auth,
	// device and DNS settings. This intentionally keeps its >=16 password
	// requirement; known 12-char legacy links are parseable syntax but are
	// NOT admitted without a separate narrowly reviewed runtime policy.
	canonical := "qwdtt://config?" + url.Values{
		"name":    {name},
		"peer":    {net.JoinHostPort(host, strconv.Itoa(dtlsPort))},
		"hashes":  {parts[5]},
		"workers": {strconv.Itoa(o.MaxWorkers)},
		"port":    {strconv.Itoa(localPort)},
		"pass":    {parts[4]},
	}.Encode()
	c, parsedName, err := qParse([]byte(canonical), o, availableKiB)
	if err != nil {
		return empty, "", err // fixed safe error codes; never echo input.
	}
	// Link import on a router must never bring up the machine's default route
	// or a TUN device. Require loopback SOCKS-only owner-lab mode.
	c.Mode = "socks"
	c.SocksListen = "127.0.0.1:1081"
	if labValidate(c) != nil {
		return fail("CLIENT_POLICY_REJECTED")
	}
	return c, parsedName, nil
}

func wdttColonImport(o qOptions) error {
	return qImportWithParser(o, wdttColonParse)
}

func wdttColonImportCLI(args []string, out, errOut io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(out, "WDTT colon offline import: -uri-file PRIVATE0600 -output-file NEW_PRIVATE0600 -auth anonymous -max-workers 9|16|18 -device EXPLICIT_ID -dns EXPLICIT_CHOICE; SOCKS loopback 127.0.0.1:1081 only, parent directories 0700, input/outputs 0600, no secret argv or network; legacy wdtt://base64(JSON) is NOT supported")
		return 0
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		fmt.Fprintln(errOut, "WDTT_COLON_PRIVATE_PROCESS_REQUIRED")
		return 78
	}
	var o qOptions
	f := flag.NewFlagSet("wdtt-colon-import", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.Input, "uri-file", "", "")
	f.StringVar(&o.Output, "output-file", "", "")
	f.StringVar(&o.Auth, "auth", "", "")
	f.StringVar(&o.Device, "device", "", "")
	f.StringVar(&o.Credentials, "credentials-file", "", "")
	f.StringVar(&o.DNS, "dns", "", "")
	f.IntVar(&o.MaxWorkers, "max-workers", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 {
		fmt.Fprintln(errOut, "WDTT_COLON_OPTIONS_INVALID")
		return 78
	}
	if err := wdttColonImport(o); err != nil {
		fmt.Fprintln(errOut, err.Error()) // fixed code only
		return 78
	}
	fmt.Fprintln(out, "WDTT_COLON_PRIVATE_SOCKS_CONFIG_CREATED")
	return 0
}
