# Experimental WDTT → SOCKS5 for Keenetic Proxy Client

**Owner laboratory only.** The existing `-config-file` sandbox currently forces
`vpn`; this opt-in mode activates the pre-existing upstream userspace
WireGuard netstack and TCP SOCKS5 server on **127.0.0.1:1081 only**.
No external Mihomo, `wg-quick`, kernel WireGuard module, kernel TUN,
Entware services, router DNS, firewall or routing rules are created.

A running SOCKS listener is **not proof** of a successful WireGuard handshake,
Internet egress, DNS confinement, or whitelisted-network operation. The
existing `go_client/socks5.go` currently supports **TCP CONNECT only**;
SOCKS5 UDP ASSOCIATE / UDP forwarding is not implemented.

## Secure opt-in

Start from the operator's existing private `0700` directory and `0600`
JSON, with the additional values:

```json
"mode": "socks",
"socks_listen": "127.0.0.1:1081"
```

Exactly those values are accepted. The old `vpn` mode and configs omitting
the two fields retain their original behavior; unknown modes, remote listens
and IPv6/unspecified/wildcard binds are rejected before network access.
Never pass VK hashes, TURN usernames/passwords or keys on the CLI.
For SOCKS mode, the received WG configuration's endpoint must precisely
match the configured local WDTT UDP listener `127.0.0.1:9000` and use IPv4
for WG address, DNS and AllowedIPs; invalid configurations fail closed
without opening SOCKS. The **full** private WG configuration is never
printed. Credentials remain 0600, parent dir 0700; upstream logs, core
dumps and STDIO suppressed; max lab duration 30 minutes.
`mode: socks` does not increase anonymous worker limits (12 requested,
9 effective on this pinned branch).

Operator-only fixed code diagnostics:
- `status`: process/GETCONF lifecycle, e.g. CONFIG_READY
- `transport-ready`: WORKER_REGISTERED (one DTLS worker)
- `getconf-status`: CONFIG_READY (WG config received and saved)
- `socks-status`: WAITING_FOR_WG, WG_STARTING, WG_CONFIG_REJECTED,
  WG_START_FAILED, SOCKS_BIND_FAILED, SOCKS_LISTENING,
  SOCKS_SERVER_FAILED or SOCKS_STOPPED.

`SOCKS_LISTENING` means the **TCP socket was bound**, not that packets
were delivered through WireGuard. Run manual owner-approved checks with
`curl --socks5-hostname 127.0.0.1:1081 --max-time 15` after starting
WDTT, compare against no-proxy control, monitor RSS/SwapFree; then stop
the exact PID. Do not enable Keenetic's Proxy connection before local
end-to-end SOCKS5 traffic is confirmed.

## Keenetic integration (after bounded acceptance)

KeeneticOS 3.9+ includes system **Proxy Client** with SOCKS5 connections in
**Other connections / Proxy connections**. Specify literal 127.0.0.1 port
1081, no auth (strict loopback only), but initially leave the connection
out of the default system and router-originated routing policies.

IMPORTANT: avoid recursive routing. VK Call HTTPS bootstrap and TURN
connections **must remain on WAN**, not routed through the Proxy Client
that depends on them. Create an isolated routing policy for one selected
test device only; do not enable proxy for all traffic, router-originated
flows or default route before measuring actual packet paths. Default-route
fallback and DNS behavior must be explicitly verified rather than
assumed. SOCKS is TCP-only in this version, so it is not a general UDP VPN.

This experimental branch does **not** alter supported KAS+WDTT 512MB+
admission or allow KAS+WDTT on 256 MB. KN-1010/256MB is operator-only
standalone ELF smoke test with an existing manually managed zRAM and
external swap. It is not an IPK, startup service or production release.
