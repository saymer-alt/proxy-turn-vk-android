// SPDX-License-Identifier: GPL-3.0-or-later
package main

// Account workers are a global budget, not multiplied by hash count.
func accountGroupRange(group, groups, workers int) (int, int) {
	base, extra := workers/groups, workers%groups
	start := group*base + min(group, extra)
	return start, start + base + min(1, max(0, extra-group))
}
