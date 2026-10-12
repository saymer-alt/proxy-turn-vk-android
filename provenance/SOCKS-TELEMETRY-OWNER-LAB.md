# WDTT owner-lab SOCKS telemetry — NC-1812 ARM64 and KN-1010 MIPSel

Date: 2026-10-12. **Experimental only**, separate from official Entware package, feeds, KAS and default Android branches.

## Physical findings (owner reports)

| Server | Location | Yandex receive | Yandex send | Yandex RTT | Ookla |
|---|---|---:|---:|---:|---|
| Germany ONYX18 `150.241.68.253:56000` | DE | 27.74 Mbps | 10.57 Mbps | 104 ms | "unstable connection", error at start of measurement |
| Netherlands ONYX18 `13.143.232.157:56000` | NL | 2.11 Mbps | 0.20 Mbps | 135 ms | same error |

Owner also described ~18 Mbps on Germany at another point; these are separate informal observations, **not a controlled repeated average**. Both profiles successfully established TCP egress via qWDTT private import and SOCKS5 on NC-1812. Germany's client was independently seen to issue `UDP_ASSOCIATE_READY` after the native Keenetic proxy initiated an association; it does not prove any UDP replies. Netherlands showed `udp-status=MISSING` *immediately after TCP-only curl*, which is expected. Same ARM64 binary, same isolated Keenetic Proxy1, Policy2 VK-Test, Bridge3 and handset in these A/B tests.

Do not interpret the Speedtest error as proof of a UDP bug or a provider block without independent reproduction. Free relay/network congestion and protocol/concurrency/MTU are competing hypotheses.

## New 10-second private telemetry

Only when `mode=socks`, store an atomic, root-private, aggregate-only `socks-telemetry.json` **in the existing private 0700 config directory**, with 0600 permissions and atomic replacement. The existing `status`, `socks-status`, `udp-status`, `getconf-status` are unchanged. Output has only fixed numeric keys, never credentials, VPN keys, raw logs, IPs, URL, payload, hostnames or timestamps of connections. Existing process-level redaction and suppressed stdout/stderr/core dumps remain in effect.

Key fields:

- TCP: `tcp_connect_requested`, `tcp_connected`, `tcp_resolve_failed`, `tcp_dial_failed`, `socks_limit_rejected`, `socks_handshake_failed`, current and peak active SOCKS sessions.
- UDP: `udp_associate_ready`, active and peak associations, failed/limit-rejected associations, valid/malformed/source-rejected datagrams, netstack write success/failure, replies delivered to the local SOCKS proxy, rejected/unsolicited responses, reply bytes.
- Runtime: uptime, Go goroutines, heap allocation, Go-managed system memory, GC count.

**Meaning:** `udp_netstack_write_ok` counts a successful userspace socket write, *not remote delivery*. `udp_reply_delivered_to_proxy` counts a successful local return to Keenetic, *not phone/application confirmation*. Absence of errors is not proof of stability. Counters reset on a new process and the file can be stale after process termination.

## Owner test procedure

1. Take a backup of the existing test ELF and keep known-good private client.json; verify the new binary with the release SHA256SUMS. Never install a test ELF over the production opkg package.
2. Do not run two WDTT instances bound to UDP9000/TCP1081 simultaneously. Stop **only the verified test process PID**; never kill all proxies or alter Mihomo Proxy0.
3. Start in the pre-existing private directory using `/absolute/wt-client-linux-ARCH -config-file /absolute/private/client.json </dev/null >/absolute/private/startup-check.log 2>&1 &` (BusyBox may lack `nohup`). No default route, KAS, autostart or permanent router policy changes.
4. Wait for `CONFIG_READY`, `SOCKS_LISTENING`, then record `socks-telemetry.json` before the phone test, immediately afterward, and after ten seconds. On NC-1812 keep handset on the isolated test SSID assigned to Proxy1.
5. Test sites/Yandex/Ookla; compare before-after **deltas** of numeric counters rather than just totals. If UDP enters but never gets a reply, this distinguishes broken data path from missing SOCKS UDP association. If `socks_limit_rejected` or `tcp_dial_failed` increases, investigate concurrency/remote TCP failure first.
6. Repeat short field test on KN-1010 (256MB) as an **unsupported standalone owner lab only** after verifying RAM headroom and memory policy; do not treat success as permission to lower official KAS+WDTT >=512MB requirement.
7. Collect only filtered numeric diagnostics, output of `/proc/<PID>/status` without command line secrets, and redacted measurement results. Keep entire private config/URI/hash out of GitHub.

## Publication boundary

Standalone experimental ARM64 and MIPSel ELF artifacts only, separately SHA-pinned. Existing on-device WDTT processes/configuration not changed from GitHub. Publishing requires complete source-locked Entware/KAS tests and local TURN/DTLS/WG SOCKS TCP+UDP fixture acceptance to pass. No production IPK/feed, no default branch or main/stable promotion, no persistent router policy or autostart.
