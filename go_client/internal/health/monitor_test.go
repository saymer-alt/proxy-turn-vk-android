// SPDX-License-Identifier: GPL-3.0-or-later
package health

import (
	"context"
	"testing"
	"time"
)

func TestTransitions(t *testing.T) {
	now := time.Now()
	o := Observation{Alive: true, Verified: true, TelemetryFresh: true, SocksOwned: true}
	response := "FRESH_RESPONSE"
	calls := 0
	m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation { return o }, Probe: func(context.Context) string { calls++; return response }}
	check := func(state string, failures int) {
		t.Helper()
		r, e := m.Check(context.Background())
		if e != nil || r.State != state || r.Failures != failures {
			t.Fatalf("%+v %v", r, e)
		}
		now = now.Add(time.Second)
	}
	check("READY", 0)
	response = "DATA_PATH_FAILED"
	check("READY", 1) // one isolated failure does not trigger recovery
	response = "FRESH_RESPONSE"
	check("READY", 0)
	response = "DATA_PATH_FAILED"
	check("READY", 1)
	check("READY", 2)
	check("DEGRADED", 3)
	if !m.result.RecoverySuggested {
		t.Fatal("manual recommendation missing")
	}
	last := m.result.LastSuccess
	response = "FRESH_RESPONSE_MISSING"
	check("DEGRADED", 3)
	if m.result.LastSuccess != last {
		t.Fatal("stale response restored health")
	}
	response = "FRESH_RESPONSE"
	check("READY", 0)
	if m.result.LastSuccess <= last || m.result.RecoverySuggested {
		t.Fatal("new successful response not recorded")
	}
	if calls != 8 {
		t.Fatal(calls)
	}
}

func TestStartingStaleTelemetryAndProxyUpDeadSocks(t *testing.T) {
	now := time.Now()
	calls := 0
	o := Observation{Alive: true, Verified: true}
	m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation { return o }, Probe: func(context.Context) string { calls++; return "SOCKS_UNAVAILABLE" }}
	for i, state := range []string{"STARTING", "STARTING", "DEGRADED"} {
		r, _ := m.Check(context.Background())
		if r.State != state || r.Failures != i+1 {
			t.Fatal(r)
		}
	}
	if calls != 0 {
		t.Fatal("stale status/telemetry must not authorize external probes")
	}
	// Proxy1 up is deliberately not an input: fresh telemetry cannot mask dead SOCKS.
	o.TelemetryFresh = true
	o.SocksOwned = true
	r, _ := m.Check(context.Background())
	if r.State != "DEGRADED" || r.Reason != "SOCKS_UNAVAILABLE" {
		t.Fatal(r)
	}
}

func TestTerminalAndCancellation(t *testing.T) {
	for _, terminal := range []string{"TIME_LIMIT", "STOPPED"} {
		now := time.Now()
		o := Observation{Alive: true, Verified: true, TelemetryFresh: true, SocksOwned: true}
		calls := 0
		m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation { return o }, Probe: func(context.Context) string { calls++; return "FRESH_RESPONSE" }}
		if terminal == "TIME_LIMIT" {
			now = now.Add(LabLimit)
		} else {
			o.Alive = false
		}
		r, _ := m.Check(context.Background())
		if r.State != terminal || calls != 0 || r.RecoverySuggested {
			t.Fatal(r)
		}
		o.Alive = true
		now = m.Started
		r, _ = m.Check(context.Background())
		if r.State != terminal {
			t.Fatal("terminal process silently renewed")
		}
	}
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation {
		return Observation{Alive: true, Verified: true, TelemetryFresh: true, SocksOwned: true}
	}, Probe: func(context.Context) string { cancel(); return "DATA_PATH_FAILED" }}
	r, err := m.Check(ctx)
	if err != context.Canceled || r.Failures != 0 || r.State != "STARTING" {
		t.Fatal(r, err)
	}
}

func TestPostProbeRevalidationAndLimit(t *testing.T) {
	for _, limit := range []bool{false, true} {
		now := time.Now()
		o := Observation{Alive: true, Verified: true, TelemetryFresh: true, SocksOwned: true}
		m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation { return o }, Probe: func(context.Context) string {
			if limit {
				now = now.Add(LabLimit)
			} else {
				o.Alive = false
			}
			return "FRESH_RESPONSE"
		}}
		r, _ := m.Check(context.Background())
		expected := "STOPPED"
		if limit {
			expected = "TIME_LIMIT"
		}
		if r.State != expected || r.LastSuccess != 0 {
			t.Fatal(r)
		}
	}
}

func TestRunCancellationDoesNotOverlapOrInventStopped(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	m := Monitor{Started: now, Now: func() time.Time { return now }, Observe: func(time.Time) Observation {
		return Observation{Alive: true, Verified: true, TelemetryFresh: true, SocksOwned: true}
	}, Probe: func(context.Context) string { calls++; return "FRESH_RESPONSE" }}
	err := m.Run(ctx, time.Hour, func(r Result) error {
		if r.State != "READY" {
			t.Fatal(r)
		}
		cancel()
		return nil
	})
	if err != context.Canceled || calls != 1 || m.result.State != "READY" {
		t.Fatal(err, calls, m.result)
	}
}
