package deploy

import "testing"

func TestCanRollback(t *testing.T) {
	cases := []struct {
		name     string
		keyEnc   string
		status   string
		releases int
		want     bool
	}{
		{"no key, no rollback", "", StatusSuccess, 5, false},
		{"first successful deploy, nothing to roll back to", "k", StatusSuccess, 1, false},
		{"two successes, one step back is possible", "k", StatusSuccess, 2, true},
		{"failed but a working version exists, restore it", "k", StatusFailed, 1, true},
		{"failed with no history, no rollback", "k", StatusFailed, 0, false},
		{"queued with no history, no rollback", "k", StatusQueued, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := canRollback(c.keyEnc, c.status, c.releases); got != c.want {
				t.Fatalf("canRollback(%q,%q,%d) = %v, want %v", c.keyEnc, c.status, c.releases, got, c.want)
			}
		})
	}
}

func TestIsHexSHA(t *testing.T) {
	good := []string{"a1b2c3d", "0123456789abcdef0123456789abcdef01234567"}
	bad := []string{"", "xyz", "ABCDEF", "12345", "g123456", "0123456789abcdef0123456789abcdef012345678"}
	for _, s := range good {
		if !isHexSHA(s) {
			t.Errorf("isHexSHA(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if isHexSHA(s) {
			t.Errorf("isHexSHA(%q) = true, want false", s)
		}
	}
}
