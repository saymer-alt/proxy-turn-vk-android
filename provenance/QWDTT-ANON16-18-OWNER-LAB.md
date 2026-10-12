# Owner-only qWDTT 16/18 anonymous experiment

Separate experimental follow-up to draft PR #8 (one-hash 9-worker).
Never affects the already validated TCP+UDP/9-worker MIPSel prerelease,
main, stable, Entware feeds, router default policy or existing local SOCKS.

## Why these two profiles need new code

The original anonymous runtime floors workers to multiples of 9.
A `qwdtt://config?...&workers=16` profile silently became 9 workers.
A `workers=18` profile has two groups of 9, requiring correct independent
hash selection and a conservative RAM admission check. The qWDTT9 importer
intentionally rejected both until reviewed.

A *private* imported qWDTT16 profile with one hash now carries:
`workers=16`, `qwdtt_requested_workers=16` and
`qwdtt_effective_workers=16`, which opt into exact 9+7 rather than
flooring to 9. A two-hash 18 profile carries exact 18 and uses 9+9
groups with hash0/hash1. The 9-worker profile still uses legacy internal
12/effective9; account profiles still cap workers at 4. Neither remote
protocol nor worker authentication is modified.

## Admission boundaries

- The import command is OFFLINE; input is private 0600 URI file in
  owner-only 0700 directory. Real full links, passwords, VK call hashes,
  device IDs and WG keys NEVER go to GitHub/logs.
- `-auth anonymous -max-workers 16`: exactly one hash and 16 requested
  workers, literal IPv4 remote peer, MemAvailable >=147456 KiB.
- `-auth anonymous -max-workers 18`: exactly TWO DISTINCT hashes and
  18 requested workers, literal IPv4 remote peer, MemAvailable >=155648 KiB.
- `-auth anonymous -max-workers 9`: existing single hash 9 worker variant,
  MemAvailable >=131072 KiB, 12 -> 9 effective.
- Unsupported worker/hash combinations, forged metadata, missing
  explicit operator worker ceiling, insufficient memory, username/password
  account quota escalation, malformed or unsafe private files rejected
  before network. Runtime AGAIN checks RAM before opening WDTT socket for
  exact 16/18; memory may have changed since import.
- `qwdtt://` profiles with DNS HOSTNAME peers (e.g. the Russian 16-worker
  public profile) are NOT accepted by this stage: no silent host DNS
  bootstrap. Would require separate safe hostname resolving architecture.
- Import success is NOT TURN allocation, GETCONF or usable TCP/UDP; users
  must select ONE owner-authorized public profile and run bounded tests.

## Synthetic acceptance

- Go tests for 16 one-hash and 18 two-hash, exactly 9+7/9+9 groups,
  no silent truncation, rejected unauthorized hash count and worker
  ceiling, admission RAM boundaries, corrupted worker metadata,
  atomic 0600 private offline JSON and account regressions.
- Full checked pinned Entware/KAS and local loopback TURN/DTLS/WireGuard
  proxy TCP+UDP acceptance before any MIPSel owner-only prerelease.
- Hardware proof requires a *new* short run and monitoring RSS/SwapFree
  on owner's KN-1010; do not infer 18-worker field performance from
  prior 9-worker ~20MiB RSS result.
- Upstream 30min internal lab maximum remains; owner uses external
  short exact-PID watchdog (60–90sec), no daemon, no OS TUN or routes.
- Only after private offline import passes should user-approved live
  single-profile qWDTT be tested, without switching router default policy.

Official KAS+WDTT min RAM still 512MB. Ordinary KAS on 256MB remains
supported; this 256MB KN1010 standalone ELF use is unsupported owner lab.
UDP SOCKS implementation remains experimental; no guarantee that VK TURN
or the remote qWDTT server permits UDP. Licensing work is intentionally
deferred as requested by the owner.
