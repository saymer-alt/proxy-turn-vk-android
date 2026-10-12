# Private qwdtt:// import

This is an offline import command of the standalone client, not the Android
importer and not a connection launcher. No real public profiles are shipped.

```
wt-client -import-qwdtt -uri-file /absolute/private/profile.uri \
  -output-file /absolute/private/client.json \
  -auth account -device YOUR_EXPLICIT_DEVICE \
  -credentials-file /absolute/private/turn-creds.json \
  -max-workers YOUR_APPROVED_DEVICE_BUDGET -dns yandex
```

**Experimental single-hash anonymous qWDTT/9-worker import** (separate
owner-only path, no TURN credential file):
```
wt-client -import-qwdtt -uri-file /absolute/private/anon9.uri \
  -output-file /absolute/private/anon9.json \
  -auth anonymous -device OWNER_EXPLICIT_DEVICE \
  -max-workers 9 -dns yandex
```
This command ONLY writes a 0600 private JSON; it **does not contact the server**
or verify the password. Do not put real URI/password/hash in terminal argv,
screenshots, public Github issues, docs or debug output.

Use a verified owner-only directory0700 and regular owner files0600. Enter the
URI and credential contents with a local private editor, not shell argv/history,
environment variables or command-line echo. Input is one exact URI with optional
final LF/CRLF. Output must be absent. Never run a complete command file blindly.
Only fixed result/error codes are printed; no URI, name, pass, hash, peer, device,
credential contents or input pathname is echoed. Import never starts a worker.

The URI requires exactly one each of name, peer, hashes, workers, port, pass.
Unknown/duplicate/empty keys, malformed escapes, controls, missing fields and
unusable values fail closed. URI length<=8192bytes, name<=128, password16..1024.
Peer is literal IPv4:port (existing runtime boundary); local port1..65535 maps
to127.0.0.1 and is checked for occupancy by a temporary exclusive bind. Start
still rechecks occupancy. Hashes are comma-separated opaque ASCII alphanumeric/
underscore/hyphen values, optionally URL-encoded; duplicates/empty values and
embedded URLs are rejected rather than silently normalized/truncated.

Auth/device/credentials/DNS and max-workers must be supplied explicitly.
Missing context produces AUTH_REQUIRED, DEVICE_REQUIRED, CREDENTIALS_REQUIRED,
DNS_CHOICE_REQUIRED or DEVICE_WORKER_BUDGET_REQUIRED, never invented defaults.
The credentials file must have an existing valid `hashes` entry with nonempty
u/p and TURN URLs for every imported hash. Import does not assert that those
credentials are fresh or authorized by a remote server. No credentials are
obtained from VK during import.

Account workers1..4 remain a GLOBAL limit. The explicit max-workers budget is
also1..4; requested workers must not exceed it, and every hash needs at least
one worker. Runtime divides the same total across hashes, without multiplying
by hash count. Groups use the existing readiness cascade and first-group
GETCONF; this does not promise failover if the first hash fails. The WireGuard
protocol, AUTH/device/expiry rules and existing worker ceiling are unchanged.

Available RAM must be >=98304KiB plus16384KiB for each worker beyond the first;
MemFree is the conservative fallback on kernels without MemAvailable. This is
an import reserve, not measured working-RSS certification. The owner must choose
the max-workers budget from actual device preflight; KAS still independently
enforces its existing ABI/total-RAM/zRAM/storage/start admission.

## Anonymous qWDTT 9: tightly bounded owner-only compatibility

The user's physical KN-1010 single-hash WDTT transport passed real VK TURN,
DTLS, GETCONF, SOCKS5 TCP, Wi-Fi phone and Netherlands egress with the
**legacy config's requested12/effective9** anonymous workers (peak RSS around
20 MiB; that is not a 24-hour RAM certification). The qWDTT URI's requested
`workers=9` and **exactly ONE VK hash** can be mapped, after explicit
`-auth anonymous -max-workers 9` operator consent, into runtime
`workers=12`. The upstream anonymous runtime floors 12 to 9 because
`workersPerGroup=9`. Private output explicitly includes
`qwdtt_requested_workers=9`, `qwdtt_effective_workers=9` metadata, which
the runtime ignores, so this is auditable and not a silent count conversion.
The raw public qWDTT link is never added to CI/GitHub.

Anonymous import requires **at least 131072 KiB MemAvailable**, single
hash, 9 workers, exactly max-workers 9, empty creds-file, literal IPv4 peer,
existing private 0700/0600 files and selected DNS/device ID. Neither
`qwdtt://workers=16` nor 18/multi-hash are accepted; they return
ANONYMOUS_WORKER_POLICY_UNRESOLVED. Account mode remains max 4 with mandatory
credential file; account 9/16/18 still fail WORKER_BUDGET_EXCEEDED.
No arbitrary worker scaling, no public VK credential guessing or rate
limit bypass. First real service test must be a separately approved,
short-lived **single server** run after local offline import passes. Auth
expiry/device-limit/server changes can still prevent real connection.

This is standalone unsupported **owner-only KN-1010 256 MB lab**, not an
exemption to the official KAS+WDTT minimum 512MB. No changes to KAS,
production packages, latest/stable, kernel TUN, host routes or DNS.

Only the existing vpn transport profile is produced: WireGuard through local
UDP, no OS routes/TUN/DNS/firewall modification. DNS choices are yandex,
doh-cloudflare, doh-google or explicit custom:IPv4. Profile name is preserved
only as private JSON metadata; the existing runtime ignores that metadata.

## Filesystem and errors

Every directory component is opened without following symlinks; private leaf
directories and files require current UID and exact modes. Inputs must be
regular, single-link and bounded. Output uses descriptor-relative random
temporary file, fsync, atomic no-overwrite link and directory fsync. Existing
files/symlinks cannot be replaced. A sync failure may leave a complete protected
destination: inspect locally; never overwrite it automatically. Core dumps are
disabled before reading secrets. Credentials remain in their private file.

After successful import use the separate existing `-config-file` command only
on an admitted isolated device. Production configs and lifecycle are unchanged.

## Verification

Synthetic tests cover URI boundaries, missing context, worker/RAM/hash budgets,
multi-hash allocation, credentials, occupied ports, private modes, symlinks,
hardlinks, no-overwrite preservation, CLI redaction and fuzz parsing. The CI
candidate runner uses pinned Entware/KAS recipes in a disposable copy, repeats
ARM64/MIPSel and two extra ELF builds, real opkg, POSIX/BusyBox lifecycle,
publication safety and local TURN/WG/Mihomo tests. New client hashes are expected
because the importer and account grouping were added; an independent build
must match them. Relay, module locks, third-party source inventory and license texts remain exact; local source headers/inventory change with the implementation. The actual
entware-go pin/recipes and KAS source are not changed by this PR. CI uploads only
JSON evidence, never ELF/IPK. Real VK/public-server/hardware tests remain separate.
