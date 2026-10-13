// SPDX-License-Identifier: GPL-3.0-or-later
package health

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var invalid = errors.New("HEALTH_PRIVATE_INPUT_OR_PROCESS_INVALID")

// ReadPrivate pins every directory component without symlinks. Only current-UID
// 0700 leaf directories and regular, single-link 0600 files are accepted.
func ReadPrivate(path string) ([]byte, time.Time, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, time.Time{}, invalid
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, time.Time{}, invalid
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, time.Time{}, invalid
		}
		fd = next
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0777 != 0700 || int(st.Uid) != os.Geteuid() {
		return nil, time.Time{}, invalid
	}
	fno, err := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, time.Time{}, invalid
	}
	f := os.NewFile(uintptr(fno), "private-health-input")
	defer f.Close()
	if unix.Fstat(fno, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || int(st.Uid) != os.Geteuid() || st.Size > 65536 {
		return nil, time.Time{}, invalid
	}
	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, invalid
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return nil, time.Time{}, invalid
	}
	return b, info.ModTime(), nil
}

func processStart(b []byte) (uint64, bool, error) {
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return 0, false, invalid
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return 0, false, invalid
	}
	ticks, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, false, invalid
	}
	return ticks, f[0] != "Z" && f[0] != "X", nil
}

type Linux struct {
	PID                 int
	Executable, Profile string
	Started             time.Time
	startTicks          uint64
	exeInfo             os.FileInfo
}

func Attach(pid int, executable, profile string) (*Linux, error) {
	if pid < 1 || !filepath.IsAbs(executable) || !filepath.IsAbs(profile) || filepath.Clean(profile) != profile {
		return nil, invalid
	}
	// Clock ticks come from AT_CLKTCK, not an assumed architecture-specific 100Hz.
	aux, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return nil, invalid
	}
	word := strconv.IntSize / 8
	var hz uint64
	value := func(b []byte) uint64 {
		if word == 8 {
			return binary.NativeEndian.Uint64(b)
		}
		return uint64(binary.NativeEndian.Uint32(b))
	}
	for i := 0; i+2*word <= len(aux); i += 2 * word {
		if value(aux[i:]) == 17 {
			hz = value(aux[i+word:])
			break
		}
	}
	if hz < 1 || hz > 100000 {
		return nil, invalid
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil, invalid
	}
	ticks, alive, err := processStart(stat)
	if err != nil || !alive {
		return nil, invalid
	}
	up, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return nil, invalid
	}
	f := strings.Fields(string(up))
	if len(f) == 0 {
		return nil, invalid
	}
	seconds, err := strconv.ParseFloat(f[0], 64)
	age := seconds - float64(ticks)/float64(hz)
	if err != nil || age < 0 || age > 365*24*3600 {
		return nil, invalid
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid
	}
	l := &Linux{PID: pid, Executable: executable, Profile: profile, Started: time.Now().Add(-time.Duration(age * float64(time.Second))), startTicks: ticks, exeInfo: info}
	o := l.Observe(time.Now())
	if !o.Alive || !o.Verified {
		return nil, invalid
	}
	return l, nil
}

func (l *Linux) Observe(now time.Time) Observation {
	o := Observation{Alive: true}
	pidPath := "/proc/" + strconv.Itoa(l.PID)
	stat, err := os.ReadFile(pidPath + "/stat")
	if os.IsNotExist(err) {
		o.Alive = false
		return o
	}
	if err != nil {
		return o
	}
	ticks, alive, err := processStart(stat)
	if err != nil {
		return o
	}
	if !alive || ticks != l.startTicks {
		o.Alive = false
		return o
	}
	path, err := os.Readlink(pidPath + "/exe")
	if os.IsNotExist(err) {
		o.Alive = false
		return o
	}
	if err != nil {
		return o
	}
	info, err := os.Stat(pidPath + "/exe")
	if err != nil {
		return o
	}
	if path != l.Executable || !os.SameFile(l.exeInfo, info) {
		o.Alive = false
		return o
	}
	cwd, err := os.Readlink(pidPath + "/cwd")
	if err != nil || cwd != l.Profile {
		return o
	}
	o.Verified = true
	b, modified, err := ReadPrivate(filepath.Join(l.Profile, "status"))
	if err == nil && !modified.Before(l.Started) && !modified.After(now) && string(b) == "TIME_LIMIT\n" {
		o.TimeLimit = true
	}
	b, modified, err = ReadPrivate(filepath.Join(l.Profile, "socks-telemetry.json"))
	var t struct {
		Schema int    `json:"schema"`
		Uptime *int64 `json:"uptime_seconds"`
	}
	age := now.Sub(modified)
	if err == nil && age >= 0 && age <= 25*time.Second && !modified.Before(l.Started) && json.Unmarshal(b, &t) == nil && t.Schema == 2 && t.Uptime != nil && *t.Uptime >= 0 && *t.Uptime <= 1800 {
		// Bind the numeric snapshot to this process's age, not a previous run.
		delta := now.Sub(l.Started) - time.Duration(*t.Uptime)*time.Second
		o.TelemetryFresh = delta >= -2*time.Second && delta <= 27*time.Second
	}
	return o
}
