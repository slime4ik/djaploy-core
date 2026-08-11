package deploy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/slime4ik/djaploy-core/internal/cfg"
)

func testCfg(jwtSecret string) *cfg.Config {
	return &cfg.Config{JWTSecret: jwtSecret}
}

func newGitLabReq(event, token, body string) (*httptest.ResponseRecorder, *gin.Context) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/gitlab/webhook", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("X-Gitlab-Event", event)
	if token != "" {
		c.Request.Header.Set("X-Gitlab-Token", token)
	}
	return w, c
}

// Cases that never reach the service (svc=nil does not panic, so the filters do their job).
func TestGitLabWebhookFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	wh := NewWebhook(nil, "unused-for-gitlab")

	pushFeature := `{"ref":"refs/heads/feature","after":"abc123","project":{"path_with_namespace":"o/r","default_branch":"main"}}`
	branchDelete := `{"ref":"refs/heads/main","after":"0000000000000000000000000000000000000000","project":{"path_with_namespace":"o/r","default_branch":"main"}}`

	cases := []struct {
		name   string
		event  string
		body   string
		expect string
	}{
		{"not a Push Hook, ignored", "Tag Push Hook", "{}", "ignored"},
		{"non-default branch, skipped", "Push Hook", pushFeature, "skipped"},
		{"branch deletion, skipped", "Push Hook", branchDelete, "skipped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, c := newGitLabReq(tc.event, "any", tc.body)
			wh.HandleGitLab(c)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.expect) {
				t.Fatalf("expected 200 with %q, got %d: %s", tc.expect, w.Code, w.Body.String())
			}
		})
	}
}

// The webhook secret is deterministic, different per project and never empty.
func TestGitLabHookSecret(t *testing.T) {
	s := &Service{cfg: testCfg("jwt-secret-1")}
	a1, a2, b := s.GitLabHookSecret("dep-a"), s.GitLabHookSecret("dep-a"), s.GitLabHookSecret("dep-b")
	if a1 == "" || len(a1) != 32 {
		t.Fatalf("expected a 32 character secret, got %q", a1)
	}
	if a1 != a2 {
		t.Fatal("the secret must be deterministic for one project")
	}
	if a1 == b {
		t.Fatal("different projects must get different secrets")
	}
	// a different server JWT secret must produce different webhook secrets
	s2 := &Service{cfg: testCfg("jwt-secret-2")}
	if s2.GitLabHookSecret("dep-a") == a1 {
		t.Fatal("the secret must depend on the server JWT secret")
	}
}
