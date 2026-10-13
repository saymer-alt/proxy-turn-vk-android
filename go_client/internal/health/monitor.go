// SPDX-License-Identifier: GPL-3.0-or-later
// Observation only. There is deliberately no process/network mutation API.
package health

import (
	"context"
	"time"
)

const LabLimit = 30 * time.Minute

type Observation struct {
	Alive, Verified, TelemetryFresh, TimeLimit, SocksOwned bool
}

type Result struct {
	State             string `json:"state"`
	Reason            string `json:"reason"`
	Failures          int    `json:"consecutive_failures"`
	CheckedAt         int64  `json:"checked_at_unix"`
	LastSuccess       int64  `json:"last_success_unix"`
	RecoverySuggested bool   `json:"recovery_suggested"`
}

// Monitor is single-caller: Run never overlaps checks and waits AFTER each check.
type Monitor struct {
	Started time.Time
	Now     func() time.Time
	Observe func(time.Time) Observation
	Probe   func(context.Context) string // fixed code; FRESH_RESPONSE is the only success
	result  Result
}

func (m *Monitor) terminal(o Observation, now time.Time) bool {
	if o.TimeLimit || now.Sub(m.Started) >= LabLimit {
		m.result.State, m.result.Reason = "TIME_LIMIT", "LAB_LIMIT_REACHED"
	} else if !o.Alive {
		m.result.State, m.result.Reason = "STOPPED", "PROCESS_EXITED_OR_IDENTITY_CHANGED"
	} else {
		return false
	}
	m.result.CheckedAt = now.Unix()
	m.result.RecoverySuggested = false
	return true
}

func (m *Monitor) Check(ctx context.Context) (Result, error) {
	if m.result.State == "" {
		m.result.State = "STARTING"
	}
	if err := ctx.Err(); err != nil {
		return m.result, err
	}
	if m.result.State == "STOPPED" || m.result.State == "TIME_LIMIT" {
		return m.result, nil
	}
	now := m.Now()
	o := m.Observe(now)
	if m.terminal(o, now) {
		return m.result, nil
	}
	reason := "PROCESS_UNVERIFIED"
	if o.Verified {
		reason = "TELEMETRY_STALE_OR_INVALID"
		if o.TelemetryFresh {
			if !o.SocksOwned {
				reason = "SOCKS_UNAVAILABLE_OR_FOREIGN"
			} else {
				// Cannot run a probe past the original WDTT session limit.
				probeCtx, cancel := context.WithDeadline(ctx, m.Started.Add(LabLimit))
				reason = m.Probe(probeCtx)
				cancel()
			}
		}
	}
	// Owner cancellation is not a failed check or a fabricated STOPPED worker.
	if err := ctx.Err(); err != nil {
		return m.result, err
	}
	now = m.Now()
	o = m.Observe(now) // a response from a process that just died cannot restore READY
	if m.terminal(o, now) {
		return m.result, nil
	}
	if !o.Verified {
		reason = "PROCESS_UNVERIFIED"
	} else if !o.TelemetryFresh {
		reason = "TELEMETRY_STALE_OR_INVALID"
	} else if !o.SocksOwned {
		reason = "SOCKS_UNAVAILABLE_OR_FOREIGN"
	}
	m.result.CheckedAt, m.result.Reason = now.Unix(), reason
	if reason == "FRESH_RESPONSE" {
		m.result.State, m.result.Failures = "READY", 0
		m.result.LastSuccess = now.Unix()
	} else {
		if m.result.Failures < 3 {
			m.result.Failures++
		}
		if m.result.Failures == 3 {
			m.result.State = "DEGRADED"
		}
	}
	m.result.RecoverySuggested = m.result.State == "DEGRADED"
	return m.result, nil
}

func (m *Monitor) Run(ctx context.Context, interval time.Duration, emit func(Result) error) error {
	for {
		r, err := m.Check(ctx)
		if err != nil {
			return err
		}
		if err = emit(r); err != nil {
			return err
		}
		if r.State == "TIME_LIMIT" || r.State == "STOPPED" {
			return nil
		}
		wait := min(interval, m.Started.Add(LabLimit).Sub(m.Now()))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
