# WDTT native SOCKS5 — experimental UDP ASSOCIATE (KN-1010 owner lab)

This is an opt-in extension of draft PR #5's **already field-verified TCP
SOCKS5** on `127.0.0.1:1081`. It uses the **same WireGuard userspace netstack**
as SOCKS TCP; no second Mihomo, host UDP outbound, kernel TUN,
route, DNS or firewall changes. It does not alter the existing TCP-only
release. No Entware IPK/startup/latest/stable is produced by this branch.

## Boundary
- `mode:socks` + `socks_listen:127.0.0.1:1081` as before; `mode:vpn`
  and existing lab settings remain unchanged. SOCKS5 clients must reach
  the TCP listener on loopback, and receive a UDP relay bound on **127.0.0.1**
  with an ephemeral UDP port. In-process WireGuard sends the outbound
  UDP payload; `net.ListenUDP` is used **only** on host loopback for
  receiving locally generated SOCKS5 datagrams.
- Supports SOCKS5 TCP CONNECT (existing) and UDP ASSOCIATE (new), RFC1928
  UDP RSV=0, FRAG=0, ATYP IPv4 or ASCII domain, port, payload.
  IPv6, fragmentation, BIND, reserved bytes, unsupported auth, malformed
  framing, oversize datagrams, unsolicited remote UDP replies and packets
  from other source ports are rejected. UDP control request destination
  must be IPv4 0.0.0.0 or the same client loopback IP.
- DNS for domain destinations is resolved by `netstack.LookupContextHost`
  **inside the WireGuard profile**, never via host DNS. The exact remote
  WG endpoint remains bound to the local WDTT UDP dispatcher.
- Per-process connection limits: 32 TCP connections, up to 4 concurrent
  UDP ASSOCIATE associations; per-association destination cache at most
  32 endpoints, expiry after 2 minutes, per-packet UDP payload max 2048
  bytes, frames max 2304 bytes. No retransmission of fragmented datagrams.
  TCP controls own their UDP associations: closing the control socket
  closes both UDP sockets and terminates forwarding.
- All passwords, VPN keys and TURN credentials remain in private
  owner-only files; zero upstream logs/core. `udp-status` emits only fixed
  `UDP_ASSOCIATE_READY` (association port created, **not** proof of UDP
  delivery) as 0600 file; multiple associations may share last-event status.

## Acceptance gates
1. Synthetic parser tests: IPv4, hostname, UDP 64/512/1000/1200/1400,
   incorrect FRAG/RSV/type/oversize, port pinning, unsolicited replies.
2. Local real loopback fixture: Pion TURN → hardened relay →
   DTLS/GETCONF → real WireGuard netstack → SOCKS TCP request and
   UDP echo (including domain via WG DNS), invalid FRAG/source, close
   association and fail closed when WDTT shuts down. Neither public VK
   nor production router is contacted. Existing Mihomo/qWDTT local
   acceptance is retained, not replaced.
3. On physical KN-1010 MIPSel: owner SHA256-verifies new standalone ELF,
   runs manually with a 60–90s watchdog and old configs held privately.
   Test UDP-ASSOCIATE with SOCKS5 client and compare external TCP/UDP;
   validate native Keenetic Proxy Client separately. Previous phone TCP
   pass was ~3.3 Mbps down / 1.5 Mbps up via NL relay; this is **NOT
   UDP performance evidence**.
4. Observe RAM/SWAP/CPU and fail-closed when WDTT stopped. Do not enable
   router default policy or remove the existing 7890 proxy during tests.

Normal KAS supports 256 MB. **KAS+WDTT support floor remains 512 MB**.
KN-1010/256 MB is separate unsupported manually controlled owner ELF lab.
qWDTT account/anonymous import, other remote profiles and direct public
VK UDP are separate follow-up gates. Licensing backlog remains deferred
per owner and is not re-opened as part of this implementation.
