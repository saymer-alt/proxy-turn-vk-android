// SPDX-License-Identifier: GPL-3.0-or-later
package main

// Numeric-only, per-process owner-lab transport visibility. Never retain or
// serialize a VK hash, TURN credential, URL, peer or device identifier here.
//
// The 18/1 vs 18/2 question requires proof that TWO separate groups actually
// have nine REGISTERED DTLS workers, not just one WORKER_REGISTERED marker.
// The counter records successful dispatcher registrations, not merely started
// goroutines / attempted TURN allocations / HTTP proxy activity.
//
// No synchronous I/O, goroutines, timers or network calls on the hot path.

import "sync/atomic"

const wdttMeterWorkerMax = 108
const wdttMeterGroupMax = 12

type wdttWorkerMeter struct {
	live [wdttMeterWorkerMax + 1]atomic.Uint32
	seen [wdttMeterWorkerMax + 1]atomic.Uint32

	active        atomic.Int64
	peak          atomic.Int64
	ever          atomic.Int64
	registrations atomic.Uint64

	groupCredOK        [wdttMeterGroupMax + 1]atomic.Uint64
	groupCredFailed    [wdttMeterGroupMax + 1]atomic.Uint64
	groupRefreshOK     [wdttMeterGroupMax + 1]atomic.Uint64
	groupRefreshFailed [wdttMeterGroupMax + 1]atomic.Uint64
	groupTurnQuota     [wdttMeterGroupMax + 1]atomic.Uint64
}

var wdttLabWorkerMeter wdttWorkerMeter

func (m *wdttWorkerMeter) registered(id int) {
	if id < 1 || id > wdttMeterWorkerMax {
		return
	}
	if !m.live[id].CompareAndSwap(0, 1) {
		return // idempotent, even if the callback was repeated by mistake
	}
	m.registrations.Add(1)
	if m.seen[id].CompareAndSwap(0, 1) {
		m.ever.Add(1)
	}
	n := m.active.Add(1)
	for {
		p := m.peak.Load()
		if n <= p || m.peak.CompareAndSwap(p, n) {
			break
		}
	}
}

func (m *wdttWorkerMeter) unregistered(id int) {
	if id < 1 || id > wdttMeterWorkerMax {
		return
	}
	if m.live[id].CompareAndSwap(1, 0) {
		m.active.Add(-1)
	}
}

func (m *wdttWorkerMeter) initialCredentials(groupID int, ok bool) {
	if groupID < 1 || groupID > wdttMeterGroupMax {
		return
	}
	if ok {
		m.groupCredOK[groupID].Add(1)
	} else {
		m.groupCredFailed[groupID].Add(1)
	}
}

func (m *wdttWorkerMeter) refreshedCredentials(groupID int, ok bool) {
	if groupID < 1 || groupID > wdttMeterGroupMax {
		return
	}
	if ok {
		m.groupRefreshOK[groupID].Add(1)
	} else {
		m.groupRefreshFailed[groupID].Add(1)
	}
}

func (m *wdttWorkerMeter) turnQuota(groupID int) {
	if groupID >= 1 && groupID <= wdttMeterGroupMax {
		m.groupTurnQuota[groupID].Add(1)
	}
}

// snapshot contains ONLY bounded numeric keys. Counters are atomic but do not
// form a transactional snapshot; a reader can observe a registering worker
// between its slot CAS and active counter increment. This is telemetry, not an
// admission / routing / health decision.
//
// Group counts are indexed by *worker ID*, not by a provided credential hash:
// worker IDs 1..9 => group 1, 10..18 => group 2. This is fixed by main.go.
func (m *wdttWorkerMeter) snapshot(dst map[string]any) {
	dst["transport_worker_active"] = m.active.Load()
	dst["transport_worker_peak"] = m.peak.Load()
	dst["transport_worker_unique_registered"] = m.ever.Load()
	dst["transport_worker_registration_events"] = m.registrations.Load()

	// Only the two groups used by owner-lab 9/1, 16/1, 18/1, 18/2
	// are exposed. No extra worker IDs, names or secret-bearing labels.
	for group := 1; group <= 2; group++ {
		live, unique := int64(0), int64(0)
		from := (group-1)*9 + 1
		for id := from; id < from+9; id++ {
			live += int64(m.live[id].Load())
			unique += int64(m.seen[id].Load())
		}
		if group == 1 {
			dst["transport_group1_active"] = live
			dst["transport_group1_unique_registered"] = unique
			dst["transport_group1_credentials_ok"] = m.groupCredOK[1].Load()
			dst["transport_group1_credentials_failed"] = m.groupCredFailed[1].Load()
			dst["transport_group1_refresh_ok"] = m.groupRefreshOK[1].Load()
			dst["transport_group1_refresh_failed"] = m.groupRefreshFailed[1].Load()
			dst["transport_group1_turn_quota_events"] = m.groupTurnQuota[1].Load()
		} else {
			dst["transport_group2_active"] = live
			dst["transport_group2_unique_registered"] = unique
			dst["transport_group2_credentials_ok"] = m.groupCredOK[2].Load()
			dst["transport_group2_credentials_failed"] = m.groupCredFailed[2].Load()
			dst["transport_group2_refresh_ok"] = m.groupRefreshOK[2].Load()
			dst["transport_group2_refresh_failed"] = m.groupRefreshFailed[2].Load()
			dst["transport_group2_turn_quota_events"] = m.groupTurnQuota[2].Load()
		}
	}
}
