// SPDX-License-Identifier: GPL-3.0-or-later
package main

// Existing conservative floors, centralized, NOT reduced by component benchmarks.
func wdttMemoryMinimum(auth string, effectiveWorkers int) (int64, bool) {
	if auth == "account" && effectiveWorkers >= 1 && effectiveWorkers <= 4 {
		return 98304 + int64(effectiveWorkers-1)*16384, true
	}
	if auth == "anonymous" {
		switch effectiveWorkers {
		case 9:
			return 131072, true
		case 16:
			return 147456, true
		case 18:
			return 155648, true
		}
	}
	return 0, false
}

func labRuntimeMemoryOK(c labConfig, available int64) bool {
	if labValidate(c) != nil {
		return false
	}
	workers := c.Workers
	if c.Auth == "anonymous" {
		workers = c.QWDTTEffectiveWorkers
		if c.Workers == 12 && c.QWDTTRequestedWorkers == 0 {
			workers = 9
		}
	}
	minimum, ok := wdttMemoryMinimum(c.Auth, workers)
	return ok && available >= minimum
}
