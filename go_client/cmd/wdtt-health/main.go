// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"wg-turn-client/internal/health"
)

func run() int {
	if len(os.Args) == 2 && os.Args[1] == "-h" {
		fmt.Println("wdtt-health -config-file /absolute/private/health.json; observation only; explicit owner target; no restart")
		return 0
	}
	if len(os.Args) != 3 || os.Args[1] != "-config-file" {
		fmt.Fprintln(os.Stderr, "HEALTH_PRIVATE_CONFIG_REQUIRED")
		return 78
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		return 78
	}
	b, _, err := health.ReadPrivate(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "HEALTH_PRIVATE_CONFIG_REJECTED")
		return 78
	}
	var cfg struct {
		PID        int    `json:"pid"`
		Executable string `json:"executable"`
		Profile    string `json:"profile"`
		Target     string `json:"target_url"`
		Interval   int    `json:"interval_seconds"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || health.ValidateTarget(cfg.Target) != nil || cfg.Interval < 10 || cfg.Interval > 60 {
		fmt.Fprintln(os.Stderr, "HEALTH_CONFIG_INVALID_EXPLICIT_TARGET_AND_INTERVAL_REQUIRED")
		return 78
	}
	l, err := health.Attach(cfg.PID, cfg.Executable, cfg.Profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "HEALTH_PROCESS_ATTACH_REJECTED")
		return 78
	}
	m := health.Monitor{Started: l.Started, Now: time.Now, Observe: l.Observe, Probe: func(ctx context.Context) string { return health.Probe(ctx, cfg.Target) }}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(os.Stdout)
	err = m.Run(ctx, time.Duration(cfg.Interval)*time.Second, func(r health.Result) error { return encoder.Encode(r) })
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "HEALTH_MONITOR_CANCELLED_WORKER_UNCHANGED")
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "HEALTH_MONITOR_OUTPUT_FAILED")
		return 1
	}
	return 0
}
func main() { os.Exit(run()) }
