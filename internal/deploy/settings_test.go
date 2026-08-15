package deploy

import "testing"

// The check path is concatenated onto the site URL, so junk is as unacceptable here as it is
// in the protected paths.
func TestCheckPathIsFiltered(t *testing.T) {
	for _, in := range []string{"", "   ", "/"} {
		got, de := normalizeCheckPath(in)
		if de != nil || got != "" {
			t.Errorf("%q should mean the site root, got %q (%v)", in, got, de)
		}
	}
	// a missing leading slash is our problem, not the user's
	if got, de := normalizeCheckPath(" healthz "); de != nil || got != "/healthz" {
		t.Errorf("expected /healthz, got %q (%v)", got, de)
	}
	if got, de := normalizeCheckPath("/api/v1/healthz/"); de != nil || got != "/api/v1/healthz/" {
		t.Errorf("expected /api/v1/healthz/, got %q (%v)", got, de)
	}
	for _, bad := range []string{"/a b", "/a?x=1", "/a#b", "/путь", `/a"b`, "/a\nb", "http://evil.com"} {
		if _, de := normalizeCheckPath(bad); de == nil {
			t.Errorf("%q must not pass", bad)
		}
	}
}

func TestCheckURLHasNoDoubleSlash(t *testing.T) {
	d := &Deployment{URL: "https://example.com/"}
	if got := d.CheckURL(); got != "https://example.com/" {
		t.Errorf("an empty path means the whole site, got %q", got)
	}
	d.ServerState.CheckPath = "/healthz"
	if got := d.CheckURL(); got != "https://example.com/healthz" {
		t.Errorf("got %q", got)
	}
}

// Django tasks run only for Django and only while the user keeps them on.
func TestDjangoTasksCanBeTurnedOff(t *testing.T) {
	d := &Deployment{}
	if !d.RunsDjangoTasks() {
		t.Error("an empty framework means django, tasks must run (older projects)")
	}
	d.ServerState.SkipDjangoTasks = true
	if d.RunsDjangoTasks() {
		t.Error("turned off by the checkbox, must not run")
	}
	d.ServerState.SkipDjangoTasks = false
	d.ServerState.Framework = frameworkOther
	if d.RunsDjangoTasks() {
		t.Error("not Django, nothing to run")
	}
}
