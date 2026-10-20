# Owner-only WDTT colon share-link import (2026-10-21) — candidate

**Status:** Draft / offline synthetic compatibility only. NOT a production importer, not an installed router binary, and not yet evidence of provider connectivity. Companion to [real-world issue #29](https://github.com/saymer-alt/proxy-turn-vk-android/issues/29), [18/1 PR #28](https://github.com/saymer-alt/proxy-turn-vk-android/pull/28).

## Why this dialect matters

The user supplied real forum-style `wdtt://host:56000:56001:9000:pass:vkHash` examples. The same colon grammar is documented by [kostfuciy/qWDTT](https://github.com/kostfuciy/qWDTT) (classic WDTT import). [ildarmaga/wdtt](https://github.com/ildarmaga/wdtt/blob/main/README.md) documents more than one WDTT share dialect, including `wdtt://base64(JSON)` created by some panels; its [API documentation](https://github.com/ildarmaga/wdtt/blob/main/docs/API.md) explicitly documents a base64-JSON panel link. **Do not confuse these two `wdtt://` schemes** or opaque RtpTun keys. Independent upstream library exposes both via separate builders ([pkg/sharelink](https://pkg.go.dev/github.com/ildarmaga/wdtt/pkg/sharelink)). Preserve explicit dialect identification in UI/importer.

Classic field syntax (SYNTHETIC placeholders ONLY):

```text
wdtt://192.0.2.77:56000:56001:9000:SYNTHETIC_PASSWORD_1234:TEST_HASH_TOKEN#test
```

IPv4 literal and three numeric UDP port fields. `dtls_port` is the outer WDTT/DTLS server port. `wg_port` is a server-internal WireGuard service port and is checked but not used as the outer peer; actual WG profile is obtained via authenticated GETCONF. `local_port` configures client loopback UDP. The colon link does **not** encode effective worker count, VK auth mode, client device identity, DNS, proxy/VPN mode or a server-side user quota. Do not invent these fields from the public share link.

## Implemented in this candidate

`wt-client -import-wdtt-colon` is **offline-only**. A new 0600 input file in a 0700 owned directory is read via existing no-symlink, no-hardlink descriptor-relative private file APIs. Generated JSON is 0600 and never overwrites an existing file. No launch, DNS or VK requests occur.

Supported **explicit** anonymous worker layouts:
- `-max-workers 9` with one unique hash: legacy runtime12/effective9.
- `-max-workers 16` with one unique hash: 9+7.
- `-max-workers 18` with one or two unique hashes: 9+9.

The user must choose worker count: classic `wdtt://` links do not include it. The importer will **never** silently assume 16 or upgrade 16 to 18 because forum descriptions or server device quotas say so. For anonymous 18/1, both groups refer to one hash as in PR #28. Runtime and import `MemAvailable` floors are inherited unchanged from existing qWDTT admission; no account quota, egress or permission relaxation.

The resulting config is always `mode=socks` with `socks_listen=127.0.0.1:1081`; no new OS TUN or default route, no WAN routing changes. The CLI has **no password/hash/URI argument**, only private file paths.

### Usage after a separately approved and SHA-verified owner-lab build

Do **not** paste a real public link into shell command arguments/history, a repo, issue, CI or support screenshot. Prepare a private file in a 0700 owned directory and chmod 0600. This example contains only placeholder paths:

```sh
./wt-client-linux-arm64 -import-wdtt-colon \
  -uri-file /private/owner-lab/profile.uri \
  -output-file /private/owner-lab/colon-config.json \
  -auth anonymous \
  -max-workers 16 \
  -device private-owner-id \
  -dns yandex
```

The importer emits only `WDTT_COLON_PRIVATE_SOCKS_CONFIG_CREATED` or fixed error codes. It cannot prove all workers registered, live TCP/UDP egress or server quotas. Final lab run, if approved, must still use private `-config-file` entry, memory check, 30min exit75 and test-only interface/policy.

### Known unsupported combinations (must not be silently admitted)

- `wdtt://base64(JSON)` from panel, URLs with passwords containing the colon separator, and hostnames: **not parsed by colon importer**. Decode the other dialect under a separately reviewed format/version-specific parser.
- `VK_HASH` placeholder rather than an actual call hash: explicitly rejected; no unapproved lookup of a real VK hash.
- Very short service-issued passwords (e.g. one user-supplied classic link was only ~12 characters). Existing private lab runtime requires `password length >= 16`; this draft retains that. **Do not pad or rewrite it**, since the WRAP/auth key would no longer match the server. Investigate exact protocol semantics before deciding whether to permit short provider-issued pass in a separate guarded profile (while preserving adequate strength/entropy).
- RtpTun opaque encoded credentials: **not WDTT raw URI passwords**.
- `workers >18`, 18/3, duplicate hash tokens, unknown query, port 0, embedded controls, unsafe file permissions, occupied local UDP port.
- `-auth account`: requires a distinct feature and explicit private VK account credentials, not represented in colon link.

## Independent checks

Synthetic tests cover 9/1, 16/1, 18/1, 18/2, group/RAM metadata, private-file exact permissions, no overwrite, forbidden argv secret flags, and rejects malformed dialects / placeholders / short passwords. No live server is contacted. Run unit/race, ARM64+MIPSel QEMU and explicit scope-guard CI before any owner physical trial. The **existing PR23 binary and 18/2 profile on NC-4210 are not modified**.

## Follow-up

1. A **separate** base64(JSON) panel-link decoder, with explicit schema/version and no secret-bearing output.
2. A narrowly reviewed short-password compatibility policy with documented format constraints and conservative admission. Do **not** globally remove qWDTT lab password minimum.
3. Real private owner-approved short smoke using a working provided colon profile on test-only interface; inspect group1/group2 counters from Draft PR #30; then independent server-panel A/B using owned test VPS.
