package deploy

import (
	"strings"
	"testing"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// Path protection has to behave the SAME no matter how the user typed the path: with or without a
// leading slash, with or without a trailing one. This walks the full path: parsePathsStr normalizes
// the leading slash, gwPathGuard normalizes the trailing one and emits three forms (/admin,
// /admin/, /admin/*).
func TestPathProtectionSlashVariants(t *testing.T) {
	inputs := []string{"/admin", "/admin/", "admin", "admin/", "  admin  ", "/admin//"}
	const wantMatchers = "/admin /admin/ /admin/*" // covers /admin, /admin/ and subpaths like /admin/login
	for _, in := range inputs {
		paths := parsePathsStr(in)
		d := &Deployment{ServerState: ServerState{VPNPaths: paths, VPN: true}}
		got := gwPathGuard(d)
		if !contains(got, wantMatchers) {
			t.Errorf("input %q: expected matchers %q, got:\n%s", in, wantMatchers, got)
		}
		if !contains(got, "10.8.0.0/24") {
			t.Errorf("input %q: the VPN subnet 10.8.0.0/24 must be trusted", in)
		}
		if !contains(got, `respond @protected "404 Not Found" 404`) {
			t.Errorf("input %q: expected a respond 404, got:\n%s", in, got)
		}
	}
}

// Several paths plus the user's own trusted IPs.
func TestPathProtectionMultiplePathsAndIPs(t *testing.T) {
	d := &Deployment{ServerState: ServerState{
		VPNPaths:   parsePathsStr("/admin, grafana/, /api"),
		VPN:        true,
		AllowedIPs: []string{"203.0.113.5", "10.0.0.0/24"},
	}}
	got := gwPathGuard(d)
	for _, w := range []string{"/admin /admin/ /admin/*", "/grafana /grafana/ /grafana/*", "/api /api/ /api/*", "10.8.0.0/24", "203.0.113.5", "10.0.0.0/24"} {
		if !contains(got, w) {
			t.Errorf("expected %q in the guard:\n%s", w, got)
		}
	}
}

// With no VPN and no trusted IPs there is NO guard, otherwise everyone would be locked out,
// including the user.
func TestPathProtectionNoTrustedNoGuard(t *testing.T) {
	d := &Deployment{ServerState: ServerState{VPNPaths: parsePathsStr("/admin"), VPN: false}}
	if got := gwPathGuard(d); got != "" {
		t.Errorf("without trusted IPs the guard must be empty, got:\n%s", got)
	}
}
