package deploy

import (
	"strings"
	"testing"
)

// We show these commands to the user and they run them on their own machine, so two things matter:
// the key line arrives intact, and an ssh user name cannot break out of the quoting.

func TestInstallCommandIsReadableAndIdempotent(t *testing.T) {
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample djaploy-ab12cd34"
	cmd := installCommand("root", "203.0.113.10", pub, "djaploy-ab12cd34")

	if !strings.Contains(cmd, "ssh root@203.0.113.10 ") {
		t.Fatalf("the server is not addressed: %s", cmd)
	}
	// The key is long: if it appears twice the command cannot be read by eye.
	// A repeat is caught by the label, so the key must appear exactly once.
	if n := strings.Count(cmd, pub); n != 1 {
		t.Fatalf("the key appears %d times, it must appear once: %s", n, cmd)
	}
	if !strings.Contains(cmd, `grep -q "djaploy-ab12cd34"`) {
		t.Fatalf("the command is not idempotent: %s", cmd)
	}
	if !strings.Contains(cmd, "~/.ssh/authorized_keys") {
		t.Fatalf("it is not visible where the line goes: %s", cmd)
	}
	// Only double quotes inside: otherwise the outer single quotes break on paste.
	inner := cmd[strings.Index(cmd, "'")+1 : strings.LastIndex(cmd, "'")]
	if strings.Contains(inner, "'") {
		t.Fatalf("a single quote inside the ssh command breaks the quoting: %s", cmd)
	}
	// The variant for the server's own console: the same thing without the ssh wrapper.
	if on := installOnServer(pub, "djaploy-ab12cd34"); on != inner {
		t.Fatalf("the two variants diverged:\n  ssh:    %s\n  server: %s", inner, on)
	}
}

func TestCommandsForAnOldKeyWithoutALabel(t *testing.T) {
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample"
	// keys we installed ourselves during a password deploy carry no label, so we match the line itself
	if on := installOnServer(pub, ""); strings.Count(on, pub) != 2 {
		t.Fatalf("without a label we match the line itself: %s", on)
	}
	if on := revokeOnServer(pub, ""); !strings.Contains(on, "grep -vF") || strings.Contains(on, "sed") {
		t.Fatalf("without a label the revoke goes by line, not by sed: %s", on)
	}
}

func TestValidAccessUser(t *testing.T) {
	ok := []string{"root", "deploy", "ubuntu", "www-data", "user_1"}
	for _, u := range ok {
		if !validAccessUser(u) {
			t.Errorf("%q must be valid", u)
		}
	}
	// anything that could break the quoting in the command we show is rejected
	bad := []string{"", "ro'ot", `ro"ot`, "root; rm -rf /", "root $(id)", "ро́от", strings.Repeat("a", 33)}
	for _, u := range bad {
		if validAccessUser(u) {
			t.Errorf("%q must not pass", u)
		}
	}
}

func TestNewAccessLabelIsUniqueAndSedSafe(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		l := newAccessLabel()
		if !strings.HasPrefix(l, "djaploy-") {
			t.Fatalf("the label must be recognisable in authorized_keys: %s", l)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				t.Fatalf("the label ends up in a sed pattern, extra characters are not allowed: %s", l)
			}
		}
		seen[l] = true
	}
	if len(seen) < 90 {
		t.Fatalf("labels repeat: %d unique out of 100", len(seen))
	}
}

func TestPlural(t *testing.T) {
	cases := map[int]string{1: "проект", 2: "проекта", 5: "проектов", 11: "проектов", 21: "проект", 104: "проекта"}
	for n, want := range cases {
		if got := plural(n, "проект", "проекта", "проектов"); got != want {
			t.Errorf("%d: got %q, expected %q", n, got, want)
		}
	}
}
