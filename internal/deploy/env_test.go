package deploy

import (
	"strings"
	"testing"
)

func TestRenderEnvDjango(t *testing.T) {
	out := renderEnv("SECRET_KEY=x", "app.example.com", frameworkDjango)
	for _, want := range []string{"SECRET_KEY=x", "DOMAIN=app.example.com", "ALLOWED_HOSTS=app.example.com", "CSRF_TRUSTED_ORIGINS=https://app.example.com", "DEBUG=False"} {
		if !strings.Contains(out, want) {
			t.Errorf("django .env: %q is missing\n%s", want, out)
		}
	}
}

func TestRenderEnvOther(t *testing.T) {
	out := renderEnv("PORT=8000", "api.example.com", frameworkOther)
	if !strings.Contains(out, "PORT=8000") || !strings.Contains(out, "DOMAIN=api.example.com") {
		t.Errorf("other .env: expected PORT and DOMAIN\n%s", out)
	}
	// Django specifics must NOT reach a non-Django stack
	for _, notWant := range []string{"ALLOWED_HOSTS", "CSRF_TRUSTED_ORIGINS", "DEBUG=False"} {
		if strings.Contains(out, notWant) {
			t.Errorf("other .env: %q should not be there\n%s", notWant, out)
		}
	}
}

func TestFrameworkOrDefault(t *testing.T) {
	if frameworkOrDefault("") != frameworkDjango {
		t.Error("an empty value must mean django (backwards compatibility)")
	}
	if frameworkOrDefault("other") != frameworkOther {
		t.Error("other must stay other")
	}
	if frameworkOrDefault("nonsense") != frameworkDjango {
		t.Error("an unknown value must fall back to django")
	}
}
