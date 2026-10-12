# Owner-lab WDTT TCP stalled-slot audit and isolated patch — 2026-10-12

Status: **proposed source-only code fix, NOT field-verified**. Stacked on PR #13; no production hardware/policy changes. Related P0 incident: #14.

## Confirmed source-level hazard

Previously, `wdttTCPConnect` set a fixed **3-minute absolute deadline** on the local SOCKS accepted socket while copying both directions concurrently. It waited for **both** io.Copy goroutines to return and only then ran deferred `remote.Close()`. The remote userspace WireGuard netstack socket had no paired deadline. A blocked remote Read could delay both-goroutine completion and strand a SOCKS slot even after local timeout/half-close. **No physical telemetry captured at the failure moment proves this was the Android app outage's root cause.**

## Narrow fix

- A single relay helper accepts the already validated local loopback SOCKS TCP conn and already dialed WireGuard netstack conn; no new network calls, no direct fallback or protocol change.
- Two TCP directions remain concurrent; an atomic progress marker is advanced **only after successful Write** on either side.
- A 180-second **inactivity** bound (not elapsed connection age) closes **both** local and remote sockets to unblock either copy. Context cancel/fatal copy error also closes both, each via `sync.Once`; this prevents the previously asymmetric close dependency for compliant net.Conn implementations.
- On normal io.Copy EOF, half-close only the destination's write side (`CloseWrite`, if supported), so delayed remote response can continue as long as actual data is passing. Last progress in either direction resets the idle timer.
- Existing 10-second SOCKS handshake and 10-second dial, four UDP ASSOCIATE slots, ARM64 high-memory 64 vs MIPSel 32 general SOCKS caps, private JSON telemetry every 10sec, and **30-minute owner-lab forced process exit** remain unchanged.
- Add fixed non-secret numeric per-process counters `tcp_relay_clean_closed`, `tcp_relay_idle_closed`, `tcp_relay_context_canceled`, `tcp_relay_copy_error_closed`, additive to v2 schema. No destinations/errors logged.
- Synthetic tests: idle blocked directions reclaimed, context cancel frees both blocked copies, continued traffic exceeds short test idle interval without premature absolute-age termination, and real TCP half-close preserves delayed opposite-direction response.

## Explicit limitations and remaining follow-up

This is **not a proven fix** for the field outage: final post-failure process liveness and port 1081 state were unavailable when owner went to bed. Incident included Chrome resets/Telegram interactive failures near ~22–24min after lab launch; late failures near ~32min can also result from the intentional **30min os.Exit(75)** even though Keenetic Proxy1 stays up. Existing 723 cumulative UDP association cap rejections on the same v2 process remain a separate issue, unchanged here.

Must pass full source-pinned multiarchitecture Entware/KAS/native TURN/DTLS/WG/SOCKS CI, then a timed physical NC-1812 A/B with a verified old binary rollback. KN-1010 256MB remains owner-only standalone; combined KAS+WDTT >=512MB unchanged. Do not merge main/stable/production before hardware acceptance. Monitor Go goroutines, RSS, new TCP after delayed half-close, Telegram and Ookla at 5/10/20min, deliberately verify 30min lab termination (stale file protection). For long-lived connections, the new 180sec idle limit remains a trade-off requiring test, and is **not** per-application reliability proof.