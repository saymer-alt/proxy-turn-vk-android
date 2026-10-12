# Owner-lab WDTT SOCKS lifecycle diagnostics v2 (2026-10-12)

**Experimental only.** This branch builds on 64-slot ARM64 / 32-slot MIPSel trial in draft PR #12; no production packages, startup services, router policies, or KAS memory floor are changed.

## Physical baseline / reason for instrumentation

The owner verified a Germany ONYX18 WDTT test on home NC-1812 via native Keenetic Proxy1 SOCKS5 + UDP, Policy2 VK-Test, Bridge3. At 101 seconds with an Ookla error, the 64-slot binary recorded **662** loopback TCP accepts, **460** rejected at 64-slot general admission, **95** separate 4-slot UDP association rejections, **96/96 TCP Connect successful** after admission, **61** valid UDP packets written to user-space WG socket and **62** replies successfully returned to the local proxy. This does not prove phone receipt or a loss-free WAN.

A **20-second quiet-phone control** (not running Speedtest) was collected on the *same running process*:
- uptime 251 -> 271 s
- `socks_accepted` 717 -> 718, `tcp_connect_requested` 145 -> 146
- `socks_limit_rejected` 460 -> 460, **zero increase**
- `udp_associate_limit_rejected` 99 -> 99, **zero increase**
- `socks_active` 10 -> 5, `go_goroutines` 316 -> 299
- `udp_associate_active` 1 -> 1, `udp_associate_ready` 12 -> 12

This is an important **idle-vs-loaded** distinction: background idleness was not continuously generating rejection floods. The captured comparison is one short informal field sample; it is not proof that Ookla alone generated the flood.

Prior A/B remote server results: Germany 27.74 down / 10.57 up Mbps / 104ms, also informally ~18 Mbps; Netherlands 2.11 down / 0.20 up / 135ms. Ookla reported unstable/error on both. A changed server did not fix it.

## Schema v2 additions and precise interpretation

The existing private `socks-telemetry.json` 0600 is written atomically every 10 seconds in the already-private 0700 test profile directory. All previous counters remain. Added **numeric aggregate-only** counters:

- `socks_handshake_active/peak/eof/timeout/other`: SOCKS protocol negotiation/early disconnects.
- `tcp_active/peak/completed/reply_failed`, and duration buckets `tcp_duration_lt_10s`, `tcp_duration_10_to_60s`, `tcp_duration_ge_60s`. These durations begin after successful SOCKS reply, not after initial TCP accept.
- `tcp_client_to_remote_bytes`, `tcp_remote_to_client_bytes`: bytes copied by the SOCKS TCP tunnel, excluding unsuccessful handshakes and protocol negotiation.
- `tcp_client_to_remote_copy_errors/timeouts` and `tcp_remote_to_client_copy_errors/timeouts`: errors returned by io.Copy in each direction; timeout is also counted as a copy error. A normal EOF returns nil from io.Copy and is not an error.
- `udp_completed`, three duration buckets, `udp_completed_without_client_data`, `udp_control_eof/other_error`, `udp_host_read_after_control_close`, `udp_host_read_unexpected_error`. A localhost socket intentionally closed after its SOCKS control TCP ended is *not* treated as unexpected receive failure.
- `process_rss_kib`, `process_rss_high_water_kib` from numeric Linux /proc/self/status and `mem_available_kib` from /proc/meminfo. Go Heap and Go Sys are not process RSS.

No per-user/IP/domain data, credentials, TURN tokens, WDTT URIs, VPN keys, DNS names, HTTP details, payload bytes or remote error strings. This is still **observability**, not a proven fix. No changing the 64/32 admission caps or the UDP 4-association cap; no new network fallback; no SOCKS protocol change; no additional high-frequency disk writes.

## Owner field A/B acceptance plan

Use SHA256-verified new executable side-by-side, retain older test binary for rollback, and stop only the verified WDTT test PID before starting this binary with the **same DE18 private profile**. Never touch Proxy0/Mihomo or change routing rules. After `CONFIG_READY`, confirm `schema=2` and the selected `socks_limit_configured` (64 on ARM64 when MemAvailable >=256MiB, 32 on MIPSel). The 10-second snapshots can lag; capture stable 20-second quiet interval and note deltas, then run one Ookla attempt, capture new snapshot and compare session/byte/duration deltas. Use only bounded single test sessions, default 30-minute maximum.

Interpret outcomes:
- Short-lived UDP associations without client packets + high `udp_associate_limit_rejected` suggest proxy/control churn.
- Many nonzero `tcp_active` and large `tcp_duration_ge_60s` with little TCP byte growth suggest long-held slots; distinguish external latency or idle sessions before modifying caps.
- Nonzero TCP transfer bytes and zero upstream dialing failures point away from a total remote TCP outage, but do not establish Ookla success.
- If the status file is from an expired 30-minute process it may be stale: verify executable PID and listener in /proc first.
- 256MB KN-1010 remains strictly standalone unsupported owner-only lab. Official KAS+WDTT >=512MB floor unchanged.

Keep this in draft until automated source/entware/local-pair CI and physical A/B on owner hardware are recorded. There are **no** public provider credentials or private profiles in this document.
