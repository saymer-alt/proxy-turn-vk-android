# Bounded packet pipe — Issue #22 (OWNER LAB ONLY)

Stacked on immutable PR #21 `f04bdbc101c8f9f86c2cc6a1cc512e9d2373504c`.
No admission on 512 MiB hardware. No router/VPS deployment or release.

## Why not LimitedAsyncPacketPipe

Locked connutil v1.0.1 `AsyncPacketPipe` delegates to limit=0. Its limited
variant checks `buf.Len() <= softLimit` before admitting an entire packet;
there is one-packet overshoot and bytes.Buffer backing capacity is not the
logical byte count. Empty packets grow pLens independently of the byte limit.
`TestLimitedPipeZeroPacketReproducer` confirms 100000 empty records are
accepted with limit=1600 and no reader. This is not a strict memory bound.
The dependency also creates an unstopped AfterFunc on every deadline wait.

## Narrow replacement and ownership

`packet_pipe.go` implements only the net.PacketConn contract needed by DTLS.
Two private fixed rings per session: **65536 bytes + 32 integer lengths per
direction**; no payload allocations, growing slice, per-wait timer or goroutine.
The byte array holds the maximum UDP datagram; the packet ring permits a burst
of 32 DTLS records (MTU 1100, 35200 bytes). Both budgets are checked before
copying; no one-packet overshoot and empty packets occupy a record slot.
On 64-bit Go the arrays alone use 131584 bytes/worker: 1184256 for 9,
2368512 for 18. Mutex/condition/deadline/timer and allocator size-class overhead
are additional; these are **pipe-only**, not total-client RAM guarantees.

Read preserves packet boundaries and reports io.ErrShortBuffer without consuming
the packet. Write copies caller bytes before returning; full queues block, never
silently drop. Close discards queued data and unblocks both directions; no graceful
drain is promised after cancellation. The fixed max write is 65536 bytes, above
the legal UDP payload limit and existing 1600/1680 relay read buffers. No wire
framing, cipher, DTLS MTU or SOCKS limits change.

Each queue has one reusable timer for the earliest future read/write deadline.
When Stop reports a pending callback, setters leave rearming to that callback
under the mutex rather than spawning another timer. Close stops the timer;
wait loops recheck deadline/closed state on every wakeup. No timer is created by
entering a wait. Concurrent operations share the bounded rings. Relay Close is
guarded by sync.OnceFunc because the TURN dependency does not serialize its
close-channel check and close against concurrent callers.

RunSession and RunPing use the same implementation. Context cancellation closes
relay and pipe, early returns join relay pumps (and session keepalive), and errors
from ping forwarding now terminate the pump. Pipe closure precedes DTLS Close
so a close-notify cannot wait on a full queue. Context cancellation also closes
the TURN transaction table/socket; RunPing has an overall 15-second context in
addition to its handshake timeout. Existing system DNS resolution is not made
context-aware by this change.

## Reproduction

Use the pinned Entware Go 1.26.1 toolchain already used by #21:

```sh
cd go_client
CGO_ENABLED=0 "$GO_BIN" test -mod=readonly -short -count=1 ./...
CGO_ENABLED=1 CC=gcc "$GO_BIN" test -mod=readonly -race -short -count=1 ./...
cd ..
sudo python3 -B tools/check_bounded_pipe_lab.py --go "$GO_BIN" \
  --work /private/new-pipe-lab --report-dir /private/new-numeric-report
```

Run only in a disposable Linux lab. The A/B tool archives the exact baseline
runtime and overlays the identical pressure test, replacing only its pipe factory.
It checks source cleanliness, records toolchain/SHAs and binary SHA256, pins two
CPUs, runs three independent processes per variant and 9/18 plan. Synthetic
backlog offers 4096 x 1600-byte records per direction, pauses consumption for two
seconds then uses a slow consumer for one second. Accepted bytes differ because
backpressure is the intended behavior; this is a stalled-queue memory comparison,
not a throughput-equivalent comparison. Normal transport runs use identical
existing local TURN/DTLS/WG/SOCKS TCP/UDP fixtures and report delivered bytes,
latency, peak RSS/VmHWM, heap, goroutines and FDs. Only lo inside fresh namespaces
is configured; no production endpoint, host route/firewall or VK credentials.

## Verification status

### Persisted native stalled-consumer measurements

Exact baseline f04bdbc versus e8c1b04 runtime, Go 1.26.1, GOMAXPROCS=2,
CPU affinity 0,1; three fresh processes per variant/worker plan. The later
e3b145f commit only changes CI evidence handling/harness logging; runtime files
are identical. JSON: `WDTT-BOUNDED-PIPE-LOCAL-PRESSURE.json`.

| Workers | Baseline VmHWM KiB (three runs) | Bounded VmHWM KiB (three runs) | Median baseline → bounded |
| --- | --- | --- | --- |
| 9 | 248300, 215192, 216800 | 14108, 14136, 14148 | **216800 → 14136** |
| 18 | 409684, 436808, 416356 | 15852, 15540, 15524 | **416356 → 15540** |

At the stalled point the baseline accepted all 73728 / 147456 offered packets;
the candidate accepted exactly **576 / 1152** (32 records x two directions x
workers). This confirms finite queue admission in real resident-memory tests.
The accepted workload intentionally differs: backpressure is the tested result,
not faster delivery. There is no total-client RSS guarantee in this table.

Pion TURN still has an unchanged 1024-entry inbound channel that drops on full;
kernel UDP buffers and WireGuard/TCP queues also remain outside this pipe budget.
No new packet-drop policy is introduced in the pipe itself. End-to-end load and
loss acceptance must consider the whole chain rather than the pipe alone.

Three additional unpaired 18-worker diagnostics on e8c1b04 all passed TCP/UDP:
HWM 126340, 120292, 122664 KiB. These are diagnostic successes, not replacements
for paired comparisons or proof that earlier failures are resolved.

### CI and functional coverage

- Native unit/race: PASS locally, including dependency reproducer, packet sizes
  0..65536, short/oversize records, both-direction pressure, 100 stop/deadline/cancel
  cycles, 9/18 slow consumers and cancelled TURN allocation in RunPing.
- ARM64 and MIPSel softfloat QEMU: PASS locally; ELF and SHA256 recorded separately.
- Paired numeric memory/full transport: PASS, numerical results below. No
  allocator-only or hardware memory qualification claimed.
- First independent Entware acceptance passed at bfcccc1. First memory CI failed
  in the unchanged 120-ms SOCKS relay progress race test. The initial dependency
  reproducer set a deadline and thus created 100000 dependency timers even on
  nonblocking writes; that unnecessary deadline was removed to avoid test-suite
  interference. The failed run is retained, not treated as passing evidence.
- Final independent CI/Entware acceptance and paired long/slow tests: PASS at
  e3b145f. Runtime source is identical to e8c1b04; later changes are reporting only.
- At e8c1b04, independent run 38409873935 passed unit/race, QEMU, all three paired
  9/18 iterations and all four long/slow runs (90-second held TCP then fresh data;
  20-ms pacing per 16-KiB read). Its final numeric artifact upload failed EACCES:
  root-owned 0600 JSON could not be read by the runner. No binary/private data was
  exposed. e3b145f assigns only the numeric output directory to the uploader and
  logs numeric HWM arrays as a fallback. The functional success is retained, but
  its missing numerical artifact is not reconstructed or presented as measured.
- Shipping 30-minute emergency exit 75, RAM floors, SOCKS 32/64 and UDP 4 caps,
  protocol/WRAP goldens are retained. Short lab tests do not prove real 30-minute
  hardware cutoff or hardware ABI/resources.

Remaining gates: actual VK refresh/provider memory, shipping cutoff on disposable
hardware, concurrent Mihomo/services, MTU/loss/no-leak, reboot/rollback, and owner
authorization for any installation. KN-1012 is not accessed or admitted.

## Final independent numeric CI — e3b145f

- [Memory/unit/race/QEMU/paired/long CI 38412455853](https://github.com/saymer-alt/proxy-turn-vk-android/actions/runs/38412455853): **SUCCESS**, numeric artifact uploaded (14-day retention).
- [Entware acceptance CI 38412455714](https://github.com/saymer-alt/proxy-turn-vk-android/actions/runs/38412455714): **SUCCESS**. Tested temporary merge c60f90869bf3209c983008a7f27b085116bd85fe has exactly the same Git tree as e3b145f: 1b3e3ec20ffcbe38ebdd516ab5e278c760c15857.
- Persistent numeric arrays, CPU/latency/bytes, SHA256, source IDs and failure history: `WDTT-BOUNDED-PIPE-RESULTS.json`. Supplemental local stalled-queue arrays: `WDTT-BOUNDED-PIPE-LOCAL-PRESSURE.json`.

### Peak resident memory (KiB)

All cells in this table are **medians of three fresh processes**, same source-locked
runtime, pinned Go 1.26.1, two CPUs and identical fixture parameters per A/B pair.
VmHWM is the kernel cumulative high-water mark; RSS is sampled every 100 ms for
the transport. Raw numeric samples remain in the CI artifact; the JSON preserves
all per-run peaks. Different machines' absolute values must not be mixed.

| Workers | Stalled-pipe VmHWM baseline → bounded | Full transport VmHWM baseline → bounded | Full transport peak sampled RSS baseline → bounded |
| --- | --- | --- | --- |
| 9 | 225220 → 17724 (-92.13%) | 165104 → 141988 (-14.0%) | 165104 → 141988 |
| 18 | 418100 → 19780 (-95.27%) | 171536 → 155136 (-9.56%) | 171536 → 155136 |

The full-transport HWM arrays are retained, including variability:

- 9: baseline [204408, 134828, 165104]; bounded [141988, 139924, 150916].
- 18: baseline [171536, 171328, 178620]; bounded [152948, 170872, 155136].

Each variant/worker plan delivered **264241152 bulk TCP bytes (252 MiB)** and
**5040000 UDP payload bytes**, across three independent runs. TCP values count
both upload and download application payload; UDP values count the sent echo
payload once. All normal traffic was verified; queue-pressure cancellation
intentionally stops producers and discards outstanding records on Close.

| Workers | Median complete-fixture CPU seconds baseline → bounded | Median TCP request seconds baseline → bounded |
| --- | --- | --- |
| 9 | 12.728 → 12.728 | 1.548 → 1.668 |
| 18 | 12.935 → 12.914 | 1.689 → 1.749 |

CPU is the whole client/server/Python fixture aggregate, not isolated WDTT CPU.
Normal-load memory improved in this series, with slightly slower median TCP
request completion; this is not a throughput increase claim. Final client samples
return to **3 goroutines / 9 FDs** for every paired normal run in both variants.
Heap allocation and resident memory are separately recorded; no heap-only claim.

### Long connections and slow consumers

Four additional fresh processes: both variants at 9/18. Each holds a real SOCKS
TCP connection for 90 seconds, verifies a fresh 1-MiB response, then performs
three TCP/UDP load rounds with 20-ms pacing per 16-KiB TCP read. All **PASS**.
One run per cell: these values are **not medians**.

| Workers | Long/slow VmHWM KiB baseline → bounded |
| --- | --- |
| 9 | 155076 → 137140 |
| 18 | 150244 → 159084 |

The 18-worker long/slow candidate is **5.88% higher**, despite normal-load median
improvement. Do not claim a universal RSS improvement or reduce RAM gates.

### Remaining blockers and limits

- No 512-MiB admission. Real ARM/MIPSel resident memory, simultaneous Mihomo and
  other services, actual VK credentials/refresh, hardware MTU/loss/no-leak,
  reboot/rollback and shipping 30-minute exit 75 remain unverified here.
- Earlier local 18-worker TCP timeout (87196db) and readiness failure (44f71ee)
  are preserved. The latter had no raw child log, so its cause cannot be proven.
  Final CI and three additional e8c1b04 18-worker diagnostics passed, but do not
  establish that all historical stalled-transport incidents are explained/fixed.
- The bounded pipe is not a bound on Pion TURN's 1024-record channel, kernel
  buffers, netstack/TCP or credential-provider memory. Saturation can still cause
  upstream UDP loss under the existing TURN policy.
- Existing synchronous system DNS resolution remains outside the pipe's context
  cancellation guarantee; the new 15-second RunPing context is not a proof of a
  strict DNS-inclusive wall-clock bound on every resolver configuration.
- Owner-test IPK acceptance is offline/lab only. Quarantine reports retain
  install_ready=false, redistribution_approved=false and public_binary_upload=false;
  IPKs are not retained/distributed. Existing packaging/license gates remain closed.

The final follow-up commit records documentation/results only and intentionally
skips duplicate CI; runtime/harness/workflow trees remain the measured e3b145f.
No merge, release, stable/main mutation, router/VPS connection or installation.
