# WDTT laboratory GETCONF status (owner-test; not production)

This branch builds on `feature/qwdtt-import-20261012`, whose pinned
`wt-client-linux-mipsle` ELF passed the KN-1010/256 MB physical smoke test.
It does not change KAS admission, IPK installation, swap, router routes, or DNS.

## Reading results

The lab client now atomically maintains three **independent** private 0600 files,
all inside its operator-owned 0700 config directory:

- `status`: legacy process lifecycle, e.g. `STARTING`, `FATAL_AUTH`,
  `CONFIG_READY`, `STOPPED`.
- `transport-ready`: `STARTING` or `WORKER_REGISTERED`. Registration
  proves a successful session handshake and dispatcher registration for at
  least one worker **but does not confirm WG config or internet access**.
- `getconf-status`: fixed enum for the distinct server-side WG config path:
  - `NOT_REQUESTED`: no attempt initiated yet in this process.
  - `GETCONF_REQUESTED`: an elected worker has begun requesting config.
  - `GETCONF_NO_CONFIG`: server explicitly answered `NOCONF`.
  - `GETCONF_TIMEOUT`: request deadline/timeout, not proof of rejection.
  - `GETCONF_DENIED`: server returned explicit `DENIED:...` auth response.
  - `GETCONF_ERROR`: another request/write/read error.
  - `GETCONF_RECEIVED`: config bytes received but not yet committed to disk.
  - `CONFIG_READY`: config safely stored as private `wg-turn.conf`.

The last completed code remains after the process stops; a new manual run
resets `getconf-status` to `NOT_REQUESTED`. A late worker cannot overwrite
a confirmed `CONFIG_READY`. These statuses contain no endpoint, hash, VK
TURN username/password, device ID, private key, wire response, or vendor log.

Operator-only read-only inspection on a router **after** the manual bounded run:

```sh
for f in status transport-ready getconf-status; do
    printf '%s=' "$f"
    cat "/opt/wdtt-lab/$f" 2>/dev/null || echo MISSING
done
[ -s /opt/wdtt-lab/wg-turn.conf ] && echo WG_CONFIG_PRESENT || echo WG_CONFIG_ABSENT
grep -E '^(MemAvailable|SwapFree):' /proc/meminfo
```

**Never print or upload** `config.json`, `wg-turn.conf`, full public
`wdtt://`/`qwdtt://` URIs, TURN creds, or debug output from upstream.
`WORKER_REGISTERED` and even `CONFIG_READY` do not prove application
traffic, routing, DNS leak safety, or operation under network allowlists.

## Verification scope

Synthetic Go fixture tests check GETCONF (NOCONF/denied/config), timeout
classification, private permissions, secret-agnostic output, and successful
CONFIG_READY terminal precedence. Hardware and public VK tests require
owner-initiated, rate-limited one-endpoint trials and separate evidence.

Experimental KN-1010 standalone ELF is **not** a supported KAS+WDTT
installation. Existing KAS 256 MB regular support and KAS+WDTT 512 MB+
supported floor remain unchanged. Do not publish IPK to production feeds,
modify KAS admission, or turn on auto-start as part of this patch.
