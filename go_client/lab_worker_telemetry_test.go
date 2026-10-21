// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// Synthetic-only: no VK API, TURN service, server endpoint, secrets or router.
func TestWDTTWorkerMeterExact18OneOrTwoHashGroups(t *testing.T) {
	for _, profile := range []string{"18/1", "18/2"} {
		t.Run(profile, func(t *testing.T) {
			m := &wdttWorkerMeter{}
			var wg sync.WaitGroup
			for workerID := 1; workerID <= 18; workerID++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					m.registered(id)
				}(workerID)
			}
			wg.Wait()

			data := map[string]any{}
			m.snapshot(data)
			want := map[string]any{
				"transport_worker_active": int64(18),
				"transport_worker_peak": int64(18),
				"transport_worker_unique_registered": int64(18),
				"transport_worker_registration_events": uint64(18),
				"transport_group1_active": int64(9),
				"transport_group2_active": int64(9),
				"transport_group1_unique_registered": int64(9),
				"transport_group2_unique_registered": int64(9),
			}
			for k, v := range want {
				if data[k] != v {
					t.Fatalf("%s: got %v, expected %v", k, data[k], v)
				}
			}
			// A second callback for an already-registered ID cannot double
			// the active count or falsely claim 19 connected workers.
			m.registered(2)
			if got := m.active.Load(); got != 18 {
				t.Fatalf("double registration counted: %d", got)
			}
			for id := 1; id <= 18; id++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					m.unregistered(id)
				}(id)
			}
			wg.Wait()
			m.unregistered(2) // idempotent teardown
			m.registered(0)
			m.registered(109)
			m.unregistered(0)
			m.unregistered(109)

			data = map[string]any{}
			m.snapshot(data)
			if data["transport_worker_active"] != int64(0) ||
				data["transport_worker_peak"] != int64(18) ||
				data["transport_worker_unique_registered"] != int64(18) ||
				data["transport_group1_active"] != int64(0) ||
				data["transport_group2_active"] != int64(0) {
				t.Fatalf("unexpected post-shutdown snapshot: %+v", data)
			}
			m.registered(10) // worker can reconnect without duplicating 'unique'
			data = map[string]any{}
			m.snapshot(data)
			if data["transport_worker_registration_events"] != uint64(19) ||
				data["transport_worker_unique_registered"] != int64(18) ||
				data["transport_worker_active"] != int64(1) {
				t.Fatal("reconnect event/unique/live contract broken")
			}
		})
	}
}

func TestWDTTWorkerMeterGroupCredentialQuotaAndPrivacy(t *testing.T) {
	m := &wdttWorkerMeter{}
	m.initialCredentials(1, true)
	m.initialCredentials(2, false)
	m.refreshedCredentials(1, true)
	m.refreshedCredentials(2, false)
	m.turnQuota(2)
	m.turnQuota(2)
	// Outside bounded group slots => ignored, never an unbounded map or
	// external string used as a label.
	m.initialCredentials(-1, true)
	m.initialCredentials(100, true)
	m.refreshedCredentials(0, true)
	m.turnQuota(100)

	data := map[string]any{}
	m.snapshot(data)
	for key, want := range map[string]uint64{
		"transport_group1_credentials_ok": 1,
		"transport_group1_credentials_failed": 0,
		"transport_group2_credentials_ok": 0,
		"transport_group2_credentials_failed": 1,
		"transport_group1_refresh_ok": 1,
		"transport_group1_refresh_failed": 0,
		"transport_group2_refresh_ok": 0,
		"transport_group2_refresh_failed": 1,
		"transport_group1_turn_quota_events": 0,
		"transport_group2_turn_quota_events": 2,
	} {
		if data[key] != want {
			t.Fatalf("%s: got %v, want %d", key, data[key], want)
		}
	}
	const secretCanary = "REAL_VK_HASH_MUST_NEVER_APPEAR"
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secretCanary) {
		t.Fatal("unexpected secret reflected into numeric telemetry")
	}
	// Private snapshot keys must contain only numbers (no strings that might
	// accidentally expose credentials or remote diagnostics).
	for key, value := range data {
		switch value.(type) {
		case int64, uint64:
		default:
			t.Fatalf("non-numeric field %s (%T)", key, value)
		}
	}
}
