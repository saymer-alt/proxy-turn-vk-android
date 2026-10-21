package main

import (
	"strings"
	"testing"
)

// Канареечные значения строго фиктивные: реальные креды/токены в тестах
// не используются и не требуются.
const (
	canaryCreds   = "CANARY-turn-creds-Qz1wYXNzd29yZA=="
	canaryCaptcha = "CANARY-captcha-token-03AGdBq2x"
	canaryUnknown = "CANARY-unknown-secret-9f8e7d6c"
)

func assertNoLeak(t *testing.T, name, safe, canary string, ok bool, wantOK bool) {
	t.Helper()
	if ok != wantOK {
		t.Fatalf("%s: loggable=%v, want %v", name, ok, wantOK)
	}
	if strings.Contains(safe, canary) {
		t.Fatalf("%s: canary leaked into log representation: %q", name, safe)
	}
}

func TestRedactStdinSensitiveCommands(t *testing.T) {
	safe, ok := redactStdinForLog("TURN_CREDS|" + canaryCreds)
	assertNoLeak(t, "TURN_CREDS", safe, canaryCreds, ok, true)
	if !strings.HasPrefix(safe, "TURN_CREDS|") {
		t.Fatalf("TURN_CREDS command name lost: %q", safe)
	}
	if !strings.Contains(safe, "<redacted>") {
		t.Fatalf("TURN_CREDS payload not marked redacted: %q", safe)
	}

	safe, ok = redactStdinForLog("CAPTCHA_RESULT|" + canaryCaptcha)
	assertNoLeak(t, "CAPTCHA_RESULT", safe, canaryCaptcha, ok, true)
	if !strings.Contains(safe, "<redacted>") {
		t.Fatalf("CAPTCHA_RESULT payload not marked redacted: %q", safe)
	}
}

func TestRedactStdinControlCommandsVisible(t *testing.T) {
	for _, cmd := range []string{"PAUSE", "RESUME", "STOP"} {
		safe, ok := redactStdinForLog(cmd)
		if !ok || safe != cmd {
			t.Fatalf("%s must stay visible by name, got %q ok=%v", cmd, safe, ok)
		}
	}
}

func TestRedactStdinUnknownNeverLogged(t *testing.T) {
	safe, ok := redactStdinForLog("SOME_NEW_COMMAND|" + canaryUnknown)
	assertNoLeak(t, "unknown command", safe, canaryUnknown, ok, false)
	if safe != "" {
		t.Fatalf("unknown command must not produce log text, got %q", safe)
	}

	safe, ok = redactStdinForLog("")
	assertNoLeak(t, "empty line", safe, canaryUnknown, ok, false)
}

func TestRedactStdinLongAndCorruptInput(t *testing.T) {
	long := strings.Repeat("A|"+canaryCreds, 4096) // ~88 KiB payload
	safe, ok := redactStdinForLog("TURN_CREDS|" + long)
	assertNoLeak(t, "long TURN_CREDS", safe, canaryCreds, ok, true)
	if len(safe) > 64 {
		t.Fatalf("redacted representation must be short, got %d bytes", len(safe))
	}

	corrupt := "TURN_CREDS|\x00\xff\xfe broken \x80 utf8 " + canaryCreds
	safe, ok = redactStdinForLog(corrupt)
	assertNoLeak(t, "corrupt TURN_CREDS", safe, canaryCreds, ok, true)

	corruptUnknown := strings.Repeat("\xff\x00", 1024) + canaryUnknown
	safe, ok = redactStdinForLog(corruptUnknown)
	assertNoLeak(t, "corrupt unknown", safe, canaryUnknown, ok, false)
}

func TestRedactStdinErrorMarkerStillSuppressed(t *testing.T) {
	// Контракт обработчика: строки с "error:tunnel stopped" отфильтрованы до
	// классификатора; классификатор не должен делать их логируемыми как
	// известные команды и не должен раскрывать их содержимое.
	line := "TURN_CREDS|error:tunnel stopped|" + canaryCreds
	safe, ok := redactStdinForLog(line)
	assertNoLeak(t, "error marker line", safe, canaryCreds, ok, true)
	if !strings.Contains(safe, "<redacted>") {
		t.Fatalf("payload must stay redacted: %q", safe)
	}
}
