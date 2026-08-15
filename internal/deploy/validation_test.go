package deploy

import "testing"

// The domain and the protected paths go into the config of the SHARED Caddy gateway that hosts every
// site on the server. So the question is not "does it look like a domain" but "can it break the neighbours".

func TestDomainCannotSmuggleAnythingIntoTheGatewayConfig(t *testing.T) {
	ok := []string{"app.example.com", "a.b.c.example.org", "xn--80ak6aa92e.com", "my-app.dev"}
	for _, d := range ok {
		if !looksLikeDomain(d) {
			t.Errorf("%q must pass", d)
		}
	}
	bad := []string{
		"",
		"example",                    // no zone
		"app.example.com, victim.ru", // a comma is a second domain in Caddy, hijacking a neighbour
		"app.example.com{",           // breaks the config block
		"app.example.com}",
		`app."example".com`,
		"app example.com",
		"http://app.example.com",
		"app.example.com/admin",
		"app.example.com:8080",
		"-bad.example.com",
		"app.example.c",
	}
	for _, d := range bad {
		if looksLikeDomain(d) {
			t.Errorf("%q must not pass", d)
		}
	}
}

func TestProtectedPathsAreFiltered(t *testing.T) {
	got := parsePathsStr("/admin,grafana,/api/v1/private")
	want := []string{"/admin", "/grafana", "/api/v1/private"}
	if len(got) != len(want) {
		t.Fatalf("got %v, expected %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, expected %v", got, want)
		}
	}
	// everything that could break the gateway config (and take the server's other sites down) is dropped
	for _, bad := range []string{"/a}", "/a{", `/a"b`, "/a'b", "/a\tb", "/админ"} {
		if len(parsePathsStr(bad)) != 0 {
			t.Errorf("%q must not reach the config", bad)
		}
	}
}

func TestServiceAndVolumeNamesCarryNoJunk(t *testing.T) {
	for _, ok := range []string{"web", "app-1", "static_volume", "my.svc"} {
		if !composeNameRe.MatchString(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", "web:\n  image: evil", "-web", "web volume", "веб"} {
		if composeNameRe.MatchString(bad) {
			t.Errorf("%q must not pass", bad)
		}
	}
}
