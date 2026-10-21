# Short server-issued passwords in classic WDTT links — owner-lab opt-in

## Evidence / problem

The owner's Oct 2026 forum excerpts contain real classic `wdtt://IPv4:dtls:wg:local:password:VKhash` links. Some issuer-provided tokens have **12 ASCII alphanumeric characters**, others 16 hexadecimal characters; **do not store real examples**, recipient IDs or server addresses in source control. Changing a real 12-character token by padding, hashing or replacing it alters the authenticated WRAP key and makes the link unusable.

Read-only source review: `go_client/wrap.go` and `server.go` both implement `deriveWrapKey` using **HKDF-SHA256** with salt `WDTT-WRAP-v1`, info `rtp-obfs/chacha20poly1305` and a **32-byte output**. Both reject empty passwords but impose **no 16-character cryptographic protocol minimum**. The server's `generatedPasswordLen = 16` is the panel's password generator choice. Our import and runtime laboratory validators separately imposed the 16-character floor as a conservative owner-lab policy.

**Security note:** HKDF is a key derivation function, not password strengthening/slow hashing. It cannot recover lost entropy. A uniformly random 12-character string from an alphabet of 62 characters has approximately 71 bits of search entropy; this is **not a guarantee** that a real issuer used secure randomness. A 16-character hexadecimal token has up to 64 bits if generated uniformly. Never infer quality from length alone. Tokens posted publicly should be treated as shared credentials and access can be revoked at any time.

## Narrow opt-in policy (Draft PR #32)

Existing `qwdtt://` private importer default: **unchanged >=16 chars**. Existing normal 16+ colon import: unchanged.

An explicit operator flag on classic colon import only:
```sh
./wt-client-linux-arm64 -import-wdtt-colon \
  -uri-file /private/owner-lab/profile.uri \
  -output-file /private/owner-lab/colon-short.json \
  -auth anonymous \
  -max-workers 18 \
  -device private-owner-device \
  -dns yandex \
  --allow-legacy-short-password
```

- No actual URI/password/hash is accepted in process argv, stdout or GitHub. Private parent directory 0700; input + output files 0600; output never overwrites. Do not put real keys in scripts.
- Only **12–15 ASCII alphanumeric bytes**, with explicit flag, in `wdtt://` colon links. Anything shorter, symbols, whitespace, separators, UTF-8 multibyte tokens, missing hash, unknown dialect or implicit auth mode is rejected.
- Importer creates `wdtt_legacy_short_password=true` metadata and `mode=socks, socks_listen=127.0.0.1:1081`. Runtime validates that exact combination and rejects a short password if marker absent, mode not socks, auth not anonymous, nonloopback listener, length 16+ with short marker, or token has invalid characters.
- The plain secret bytes are preserved **exactly**. A synthetic 12-byte WRAP HKDF golden output is tested separately (no real key).
- No new permissions: same 9/1,16/1,18/1,18/2 and MemAvailable gates, same TURN/VK credentials logic, same 30-minute exit75, no daemon/default WAN routing/KAS change. This is a parser + private runtime validation exception only.
- Merely importing proves syntax and policy, **not** that the issuer server is online, allows that token, 18 workers register or SOCKS UDP works.

## Test and release gates

Synthetic unit tests should verify: default reject/explicit accept, real-like 12/13/15-length token preservation, exact HKDF output, ordinary qWDTT still rejects, malformed tokens/11 characters rejected, modified local JSON marker or auth/mode denied, exact RAM floor and no-overwrite/0600 file. Dedicated scoped Go unit/race and ARM64/MIPSel QEMU tests required, with no publicly uploaded binary or keys. Existing whole-chain PR23 immutable checker may reject any source change by design; it must not be bypassed.

Next owner-approved step: build source-hashed private ARM64 candidate from **reviewed composed PR28 + PR30 + PR31 + PR32**, then test one authorized forum colon link from `/opt` on the isolated NC-4210 SOCKS route, starting with a short TCP probe and existing 30-minute stop guard. For a proper 18/1 measurement, include PR30 counters and verify two separate groups actually register. The unrelated legacy `wdtt://base64(JSON)` panel links require their **own** parser and schema checks.
