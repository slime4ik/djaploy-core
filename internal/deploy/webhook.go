package deploy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Webhook receives push events from the GitHub App and starts an automatic deploy (CD).
// It is registered on the same URL as the auth webhook, and main.go routes by X-GitHub-Event.
type Webhook struct {
	svc    *Service
	secret string
}

func NewWebhook(svc *Service, secret string) *Webhook {
	return &Webhook{svc: svc, secret: secret}
}

func (w *Webhook) Handle(c *gin.Context) {
	event := c.GetHeader("X-GitHub-Event")

	// GitHub sends a ping when the webhook is created, and it marks the hook broken unless we answer 200.
	if event == "ping" {
		c.JSON(http.StatusOK, gin.H{"status": "pong"})
		return
	}
	if event != "push" {
		c.JSON(http.StatusOK, gin.H{"status": "ignored"})
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	if !validSignature(c.GetHeader("X-Hub-Signature-256"), body, w.secret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad signature"})
		return
	}

	var p struct {
		Ref        string `json:"ref"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			FullName      string `json:"full_name"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
		// who pushed: in the activity feed an "auto deploy" with no author looks like magic,
		// this way you can see whose push triggered it
		Pusher struct {
			Name string `json:"name"`
		} `json:"pusher"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}

	// We only deploy a push to the DEFAULT branch, and never a branch or tag deletion.
	defaultRef := "refs/heads/" + p.Repository.DefaultBranch
	if p.Deleted || p.Ref != defaultRef {
		c.JSON(http.StatusOK, gin.H{"status": "skipped", "reason": "не дефолтная ветка или удаление"})
		return
	}

	pusher := p.Sender.Login
	if pusher == "" {
		pusher = p.Pusher.Name
	}
	triggered, reason := w.svc.RedeployForCD(c.Request.Context(), p.Repository.FullName, ProviderGitHub, pusher)
	log.Printf("webhook push %s ref=%s → cd=%v (%s)", p.Repository.FullName, p.Ref, triggered, reason)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "redeploy": triggered, "reason": reason})
}

// HandleGitLab is the GitLab push webhook, which the user adds to their project by hand under
// Settings then Webhooks. Authentication is a plain secret in X-Gitlab-Token, because GitLab has
// no HMAC. Each project has its own secret, verified inside RedeployForGitLabCD.
func (w *Webhook) HandleGitLab(c *gin.Context) {
	if c.GetHeader("X-Gitlab-Event") != "Push Hook" {
		c.JSON(http.StatusOK, gin.H{"status": "ignored"})
		return
	}
	var p struct {
		Ref      string `json:"ref"`
		After    string `json:"after"`         // 000..0 = удаление ветки
		UserName string `json:"user_username"` // кто запушил (для ленты активности)
		Project  struct {
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
		} `json:"project"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}
	defaultRef := "refs/heads/" + p.Project.DefaultBranch
	if p.Ref != defaultRef || strings.Trim(p.After, "0") == "" {
		c.JSON(http.StatusOK, gin.H{"status": "skipped", "reason": "не дефолтная ветка или удаление"})
		return
	}
	triggered, reason := w.svc.RedeployForGitLabCD(c.Request.Context(),
		p.Project.PathWithNamespace, c.GetHeader("X-Gitlab-Token"), p.UserName)
	log.Printf("gitlab webhook push %s ref=%s → cd=%v (%s)", p.Project.PathWithNamespace, p.Ref, triggered, reason)
	if reason == "bad token" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "redeploy": triggered, "reason": reason})
}

// validSignature verifies GitHub's HMAC-SHA256 signature.
// An empty secret means reject (fail safe), otherwise anyone could trigger a redeploy.
// For CD, set GITHUB_WEBHOOK_SECRET to the same value as in the GitHub App settings.
func validSignature(sig string, body []byte, secret string) bool {
	if secret == "" {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(sig, prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.TrimPrefix(sig, prefix)))
}
