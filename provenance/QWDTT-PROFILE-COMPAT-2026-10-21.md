# Field qWDTT compatibility catalog — 2026-10-21 (SANITIZED)

**Owner research / Draft follow-up to PR #23.** Source: user-supplied Telegram excerpts dated Oct 04–17 2026, including repeated reposts. No untrusted live links, VK hashes, public server passwords, device IDs, RtpTun encoded access keys or recipient identifiers are stored here. Use synthetic data exclusively in automated tests; do not paste real profiles into GitHub.

Related: [Issue #27](https://github.com/saymer-alt/proxy-turn-vk-android/issues/27), [PR #23](https://github.com/saymer-alt/proxy-turn-vk-android/pull/23), [roadmap #25](https://github.com/saymer-alt/proxy-turn-vk-android/issues/25).

## Deduplicated shapes

| Observed date | Distinct profile shape | Advertised workers | VK hash count | Peer kind | Client state |
|---|---|---:|---:|---|---|
| Oct 04 | DE / NL legacy | 9 | 1 | IPv4 literal | Existing anonymous import supported |
| Oct 08 | DE password rotation | 9 | 1 | IPv4 literal | Existing anonymous import supported |
| Oct 11 | DE / NL expanded | 18 | 2 | IPv4 literal | PR #23 owner-lab supports exact 9+9 |
| Oct 11 | WARP Russia | 16 | 1 | DNS hostname | Not supported because current import requires literal IPv4; 16/1 worker plan itself supported |
| Oct 17 | DE / NL expanded | 18 | 1 | IPv4 literal | New **18/1** candidate addressed by this draft |
| Oct 17 | Finland, two alternative keys | 18 | 1 | IPv4 literal | Same **18/1** worker shape; passwords are alternatives, not concurrent test profiles |
| Undated mixed reposts | Russia / NL / Russia YouTube `wdtt://` | Not encoded | 1 | IPv4 literal | Requires a separate format importer; several short passwords fail current private lab minimum |
| Undated mixed reposts | RtpTun opaque encoded keys | Not encoded | Not applicable | Encoded | Distinct key format: **not** a raw WDTT password, not subject to naive conversion |

Published limits (50, 99, 999/1000 users/devices) are publisher claims and cannot be used as permission to run automated load or infer VK's per-hash allocation budget. Oct 17 is more recent than Oct 11 but there is no verified service liveness, key expiry or ownership in these posts. Publisher says do not add DE/NL replacements if prior key already works.

## Narrow experimental change in this draft

A real `qwdtt://` import encodes `workers=18` and exactly one unique VK call hash. Earlier private importer and lab runtime accepted 18 only when `len(hashes)==2`. But the existing native worker scheduler runs two 9-worker groups and calls `tp.Hashes[hashIndex%len(tp.Hashes)]` from `group.go`. For one hash, both independent groups use that same one. Therefore this draft changes **only anonymous 18's allowed hash cardinality 2 → 1 or 2**, at both private import and runtime validation. It does **not** claim VK supports 18 live TURN allocations on that call.

- 9/1 retains legacy requested 12 → effective 9, 16/1 retains 9+7, 18/2 retains 9+9 with different hashes, and account mode remains capped at four global workers.
- Exact `workers=18`, `qwdtt_requested_workers=18`, `qwdtt_effective_workers=18` fields remain mandatory: no silent truncation or forged metadata.
- Minimum `MemAvailable` for 18 remains **155648 KiB** at import and runtime. Do not replace available RAM with swap capacity or relax during failures.
- `hashes=alpha,alpha` remains rejected by the URI importer: one hash means **one literal hash listed once**, reused by group selection, not duplicated to game validation.
- No endpoint hostname support, short-password relaxation, broader listener, new privilege, auto-start, KAS policy, router setting, package/release, default route or extra transport permission.
- 30-minute experimental self-termination (exit 75), local loopback SOCKS5 only, 0700 root-owned private lab directory, 0600 config remain unchanged.
- All test inputs are synthetic (reserved `192.0.2.0/24` addresses, dummy hashes/passwords). No public live profile required to test parser and group arithmetic.

## Test stages (never conflate)

1. **Offline parser + private-file unit tests:** 18/1 and 18/2 import; correct 9+9 group index/hash mapping; boundary `MemAvailable=155647` reject and `155648` accept; 18/3, duplicate hashes, altered effective/requested metadata, account quota escalation and hostnames rejected; existing 9/1 and 16/1 remain green.
2. **CI functional tests:** Go unit/race, ARM64/MIPSel builds/QEMU and pinned Entware acceptance; synthetic TURN/DTLS/WG/SOCKS local loopback, TCP and UDP. Review final CI and artifacts before declaring code acceptance.
3. **Physical owner test (separate human go/no-go):** preserve existing 4210 `/opt/wdtt-lab4210` verified PR23 binary and DE18/two-hash config as control. New one-hash build must carry its own source/ELF/SHA256; compare matched workers on the same router after verifying fail-closed isolation. Sample VmHWM/RSS, MemAvailable/PSI/swap, TCP+UDP data, GETCONF, exact exit75/port close. Do not run automatic probes against publisher's public servers, rotate keys arbitrarily or assume all 18 workers can acquire TURN credentials.

## Deferred compatibility (out of scope)

- Hostname peers: separate ADR for deterministic resolver, pinning and avoiding tunnel recursion/DNS leaks; not blanket `net.LookupIP` in import.
- `wdtt://` parser, 1-hash/unspecified-worker policy, short service-issued passwords: separate review for wire compatibility and private-file validation, do not simply lower 16-byte lab minimum.
- RtpTun encoded keys: document format and license only with authorization; do not decode and publish keys or incorrectly translate as qWDTT/WDTT.
- Expiry, device quotas, fallback and VK credential refresh/rate limits: field behavior unknown and must not be inferred from source posts.

**Status:** candidate-only until independent CI and operator field acceptance. Nothing here authorizes deployment to active routers, direct network route changes, or promotion/merge of PR #23.
