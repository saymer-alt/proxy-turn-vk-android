# WDTT NC-1812 owner-lab: SOCKS5 saturation and controlled A/B cap test

Physical telemetry captured 2026-10-12 on real NC-1812 ARM64. This document supplements `provenance/SOCKS-TELEMETRY-OWNER-LAB.md`.

## Proven baseline

The owner installed SHA-verified ARM64 `wdtt-owner-lab-telemetry-4b431c203285`, started the old German ONYX18 profile via separate binary and recorded:

- `/proc` confirmed telemetry binary, status/getconf/transport all READY, SOCKS listener ready.
- Direct SOCKS HTTPS external egress `150.241.68.253` / `loc=DE` / `warp=off`.
- At uptime 41 seconds, `socks_peak=32`, `socks_limit_rejected=23`, `socks_accepted=75`, `socks_active=20`, `tcp_connect_requested=47`, `tcp_connected=46`, `tcp_dial_failed=0`, `tcp_resolve_failed=0`.
- `udp_associate_ready=4`, `udp_associate_peak=4`, `udp_associate_limit_rejected=0`, `udp_client_valid_packets=37`, `udp_netstack_write_ok=37`, `udp_reply_delivered_to_proxy=42`, `udp_netstack_write_failed=0`. At least some two-way UDP traffic passed at the local SOCKS level.
- Goroutines 349, Go heap 43,375,296 B, Go system memory 60,737,816 B, 7 GC. These are NOT RSS/CPU usage.
- This snapshot may have included browsing and/or speed tests; owner did not identify exact timing for Ookla in the log. Causation of Ookla error by 32-slot rejection remains **hypothesis**. Independently proven: the local SOCKS admission limit was reached and 23 connections rejected.

## One-variable experimental change

Baseline: 32 maximum client sockets (TCP CONNECT and UDP ASSOCIATE share cap) on every architecture.

Candidate: ARM64 with **/proc/meminfo MemAvailable >=262144 KiB at listener start** receives 64 client slots; ARM64 below that floor stays 32; all non-ARM64 including KN-1010 MIPSel remain 32. UDP-association cap unchanged at 4. No effects on wire protocols, addresses, secrets, encryption, existing production policies or official 512 MB KAS minimum. `socks_limit_configured` is emitted in aggregate telemetry so hardware owner knows which cap actually applied.

Why: isolate whether the 23 observed refusals were the immediate cause of multi-connection test failure. Avoid pretending that 64 automatically fixes Ookla. Additional active connection slots may increase goroutines, latency or memory under poor relay conditions; only owner-enabled A/B with before/after counters. **Do not test at low RAM on 256-MB MIPSel as if ARM64 limits apply.**

## Acceptance and operator comparison

Build accepts only on pinned source SHA and full native Entware/KAS/local-pair fixture CI. Publish standalone ELF checksum, nonlatest prerelease, draft PR. No auto-start or production KAS, feed, IPK or stable branch changes.

On the NC-1812 owner should preserve the previous known-good ELF, stop only the verified WDTT owner test process, select same DE18 private profile, start candidate on existing loopback port and confirm `socks_limit_configured=64` (or 32 if memory floor not met). Collect timestamp-free `socks-telemetry.json` immediately before and 10 seconds after identical Ookla/Yandex tests, plus `/proc/<PID>/status` for RSS. Compare increments to `socks_limit_rejected`, `tcp_dial_failed`, UDP counts, and concurrent peak. Do not publish credentials, VK hash, private URI or WG config. If 64 refuses connections or Ookla still fails, prefer deeper protocol/MTU and latency investigations rather than blindly raising the cap again.
