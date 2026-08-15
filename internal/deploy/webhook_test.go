package deploy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func newReq(event, sig, body string) (*httptest.ResponseRecorder, *gin.Context) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	c.Request.Header.Set("X-GitHub-Event", event)
	if sig != "" {
		c.Request.Header.Set("X-Hub-Signature-256", sig)
	}
	return w, c
}

func TestWebhookScenarios(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "s3cr3t"
	// svc=nil: none of the cases below reaches RedeployForCD (a push to the default branch is not among them)
	wh := NewWebhook(nil, secret)

	pushDefault := `{"ref":"refs/heads/main","deleted":false,"repository":{"full_name":"o/r","default_branch":"main"}}`
	pushFeature := `{"ref":"refs/heads/feature","deleted":false,"repository":{"full_name":"o/r","default_branch":"main"}}`
	branchDelete := `{"ref":"refs/heads/main","deleted":true,"repository":{"full_name":"o/r","default_branch":"main"}}`

	cases := []struct {
		name   string
		event  string
		sig    string
		body   string
		expect int
	}{
		{"ping → 200", "ping", "", "", http.StatusOK},
		{"not a push, ignored", "star", sign(secret, "{}"), "{}", http.StatusOK},
		{"push with a bad signature, 401", "push", "sha256=deadbeef", pushDefault, http.StatusUnauthorized},
		{"push to a non-default branch, skipped", "push", sign(secret, pushFeature), pushFeature, http.StatusOK},
		{"push deleting a branch, skipped", "push", sign(secret, branchDelete), branchDelete, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, c := newReq(tc.event, tc.sig, tc.body)
			wh.Handle(c)
			if w.Code != tc.expect {
				t.Fatalf("expected %d, got %d (body: %s)", tc.expect, w.Code, w.Body.String())
			}
			// a non-default push must not call RedeployForCD (svc=nil did not panic, so it did not)
			if tc.name == "push to a non-default branch, skipped" && !strings.Contains(w.Body.String(), "skipped") {
				t.Fatalf("expected skipped, body: %s", w.Body.String())
			}
		})
	}
}

func TestSignatureEmptySecretRejected(t *testing.T) {
	// fail safe: with no secret every webhook is rejected, otherwise anyone could trigger a redeploy
	if validSignature("sha256=whatever", []byte("x"), "") {
		t.Fatal("an empty secret must reject every webhook")
	}
	if validSignature("sha256=bad", []byte("x"), "secret") {
		t.Fatal("a wrong signature must be rejected")
	}
}
