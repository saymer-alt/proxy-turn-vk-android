# WDTT owner field compatibility combined candidate — 2026-10-21

**Draft integration only.** Combines reviewed source changes already tested independently in [PR #28](https://github.com/saymer-alt/proxy-turn-vk-android/pull/28), [PR #30](https://github.com/saymer-alt/proxy-turn-vk-android/pull/30), [PR #31](https://github.com/saymer-alt/proxy-turn-vk-android/pull/31) and [PR #32](https://github.com/saymer-alt/proxy-turn-vk-android/pull/32). Based on PR32 head `8cd625f983cf8fe745cecfd0bd570bc8838daff5`, copies EXACTLY five code/test files from PR30 head `7e28dccc3de7a2f260dac7f9f1de09d82bb75c9d`. This integration does **not** merge those PRs into main/stable and does not change production Keenetic/VPS.

## Features and source inheritance

| Area | Source | What the combined lab binary implements |
|---|---|---|
| 18/1 / 18/2 worker plans | PR28, PR32 inheritance | Actual 9+9 groups, one or two hashes, explicit 152MiB MemAvailable admission, original 30min exit75 unchanged |
| Worker diagnosis | PR30 | Numeric `transport_worker_active/peak/unique_registered`, per-group 9+9 registered and credential/refresh/quota counters in existing private `socks-telemetry.json`; no secret-bearing strings |
| Classic `wdtt://` links | PR31 | Strict colon link parser; operator supplies worker count 9/16/18 and anonymous/own device/DNS; 0600 private input and no-clobber output; loopback SOCKS mode only |
| Issuer short password | PR32 | Explicit `--allow-legacy-short-password` only for 12..15 ASCII alphanumeric classic colon `wdtt://` tokens. Other links >=16 as before, no padding or re-encoding; marked and checked again at runtime |
| Bounded packet pipe | PR23 parent | Existing low-memory bounded transport, no broad buffers/route changes |
| Isolated deployment | PR23 parent | Fixed SOCKS `127.0.0.1:1081`, private root files, no daemon, no system TUN/default route |

## CI/build and provenance expectations

- Independent **integration** gate must run all Go short unit and race tests, synthetic 18/1/18/2 plus short-pass/colon/group QEMU ARM64+MIPSel tests, and crosscompile two standalone Go ELFs. It does **not** contact public VK, public server, Keenetic or installed LucX.
- Require diff allowlist **exactly 7 files** relative to PR32 SHA: `go_client/lab_worker_telemetry.go`, `go_client/lab_worker_telemetry_test.go`, `go_client/session.go`, `go_client/group.go`, `go_client/socks_telemetry.go`, this document and the integration workflow. Assert full process 30min cutoff, admission and private parser source unchanged. This is a new independent integration test; do NOT bypass/edit existing older immutable PR23 source checker.
- GitHub Actions artifact contains SHA256 manifest, `BUILD-INFO.txt` with exact source SHA, `wt-client-linux-arm64` and `wt-client-linux-mipsle` only. **No full release tag, IPK, KAS integration, auto-run script, provider key or server credentials.** Retention at most 14 days. Action artifact access may be account-permission controlled.
- Passing tests proves code builds for both targets and synthetic features compose; it does **not** prove live 18/18 worker allocations, actual short public credential acceptance, UDP egress, 30min memory, strict Wi-Fi fail-closed or full Entware/KAS external integration.

## Owner field trials after separate go/no-go

1. Keep existing NC-4210 original PR23 executable SHA256 `331e7274fb41c54b7de3434f2a86d370b7bf54b706f71ad067bde2fc8e592570`, private 18/2 config, production routes and all services unchanged. The proven 120s HTTPS SOCKS PR23 smoke had VmHWM **26744 KiB**, but only **one** TCP completed; no UDP or 30min exit75. No automatic start.
2. Before new real trial, download and independently check integrated artifact and exact source SHA. Use separate 0700/0600 private lab directory/files to avoid overwriting the original executable or profile. Permission/port/memory preflights for BusyBox on NC-4210: BusyBox `timeout` unavailable and `stat -c` unsupported.
3. Test **one publisher-authorized** colon short token and qWDTT 18/1 one at a time. Measure actual group1/group2 DTLS registration, credential/refresh/quota counts, GETCONF, SOCKS TCP+UDP and RSS/PSI/Swap. Validate absence of fallback with a test-only client; do not infer no leaks solely from proxy status.
4. After short trial and rollback verification, 30min memory/exit75 and controlled owner VPS panel lab. No unattended public endpoint scan or key brute-force.
5. **Memory optimization remains an explicit follow-on after comparable 30min load metrics**: do not merge more buffer changes merely because the 4210 shows a small 120s RSS. Compare same build/hardware/load to PR23, consider allocation reuse/scratch and TURN concurrency only when profiles are field-tested. Track in existing #25/#29 or a dedicated measurement issue.
