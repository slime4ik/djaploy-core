package deploy

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/slime4ik/djaploy-core/internal/ratelimit"
)

type Handler struct {
	svc *Service
	// Anti-abuse on the expensive endpoints. Deploy and access check open SSH to ANY public IP the
	// user names. Without a limit the service becomes a convenient password bruteforcer and port
	// scanner driven by someone else's hands (the fallback password path allows exactly that).
	rl *ratelimit.Limiter
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc, rl: ratelimit.New()} }

// tooOften is the shared 429 reply. The key must include the user so one cannot block everyone.
func (h *Handler) tooOften(c *gin.Context, key string, max int, per time.Duration) bool {
	if h.rl == nil || h.rl.Allow(key, max, per) {
		return false
	}
	c.JSON(http.StatusTooManyRequests, gin.H{"error": &DeployError{
		Code:    "too_often",
		Message: "Слишком много попыток подряд.",
		Hint:    "Подожди пару минут и повтори. Если упёрся в это на обычной работе, напиши нам.",
	}})
	return true
}

// POST /api/v1/deploy starts a deploy. 202 + DeploymentView (with id), then the frontend tails the log.
func (h *Handler) Create(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "не авторизован"})
		return
	}
	// 10 deploy starts per 10 minutes per user: never in the way of normal work, and it makes guessing
	// passwords for other people's servers through our infrastructure pointless.
	if h.tooOften(c, "deploy:"+userID, 10, 10*time.Minute) {
		return
	}
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": &DeployError{
			Code: "bad_input", Message: "Не разобрал запрос.", Hint: "Заполни форму заново.",
		}})
		return
	}
	dep, de := h.svc.Start(c.Request.Context(), userID, req)
	if de != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": de}) // структурная ошибка с подсказкой
		return
	}
	c.JSON(http.StatusAccepted, dep.View())
}

// POST /api/v1/deploy/:id/redeploy updates the project over the stored key, with no form to fill.
func (h *Handler) Redeploy(c *gin.Context) {
	userID := c.GetString("user_id")
	dep, de := h.svc.Redeploy(c.Request.Context(), c.Param("id"), userID)
	if de != nil {
		code := http.StatusUnprocessableEntity
		if de.Code == "forbidden" {
			code = http.StatusForbidden
		} else if de.Code == "not_found" {
			code = http.StatusNotFound
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusAccepted, dep.View())
}

// POST /api/v1/deploy/:id/rollback rolls back to the previous version.
func (h *Handler) Rollback(c *gin.Context) {
	userID := c.GetString("user_id")
	dep, de := h.svc.Rollback(c.Request.Context(), c.Param("id"), userID)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusAccepted, dep.View())
}

// GET /api/v1/deploy/:id/server-stats returns a snapshot of server resources (disk, RAM, containers).
func (h *Handler) ServerStats(c *gin.Context) {
	userID := c.GetString("user_id")
	stats, de := h.svc.ServerStats(c.Request.Context(), c.Param("id"), userID)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// GET /api/v1/deploy/:id/gitlab-webhook returns the URL and secret for setting up the CD webhook
// in GitLab by hand, since GitLab cannot install a hook for us without a write scope.
func (h *Handler) GitLabWebhookInfo(c *gin.Context) {
	userID := c.GetString("user_id")
	dep, err := h.svc.Find(c.Request.Context(), c.Param("id"), userID)
	if errors.Is(err, ErrForbidden) {
		c.JSON(http.StatusForbidden, gin.H{"error": "нет доступа"})
		return
	}
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "деплой не найден"})
		return
	}
	if !dep.IsGitLab() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "проект не из GitLab"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"url":    h.svc.cfg.PublicURL + "/api/v1/gitlab/webhook",
		"secret": h.svc.GitLabHookSecret(dep.ID),
	})
}

// PATCH /api/v1/deploy/:id/cd turns auto deploy on push on or off.
func (h *Handler) ToggleCD(c *gin.Context) {
	userID := c.GetString("user_id")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	if err := h.svc.SetCD(c.Request.Context(), c.Param("id"), userID, body.Enabled); err != nil {
		if errors.Is(err, errCDPaidOnly) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Авто-деплой доступен на тарифах Про и Макс. Оформи подписку на дашборде."})
			return
		}
		if errors.Is(err, errCDDemo) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Для демо-проекта авто-деплой недоступен — пушить в общий демо-репозиторий нельзя."})
			return
		}
		if errors.Is(err, ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "нет доступа"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "деплой не найден"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"cd_enabled": body.Enabled})
}

// GET /api/v1/deploy/:id/app-logs returns the project's container logs from the user's server.
func (h *Handler) AppLogs(c *gin.Context) {
	userID := c.GetString("user_id")
	logs, de := h.svc.AppLogs(c.Request.Context(), c.Param("id"), userID)
	if de != nil {
		code := http.StatusUnprocessableEntity
		if de.Code == "forbidden" {
			code = http.StatusForbidden
		} else if de.Code == "not_found" {
			code = http.StatusNotFound
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// DELETE /api/v1/deploy/:id removes the project.
// ?teardown=1 stops the containers; ?purge=1 cleans the server fully (down -v and rm of the folder).
func (h *Handler) Delete(c *gin.Context) {
	userID := c.GetString("user_id")
	teardown := c.Query("teardown") == "1" || c.Query("teardown") == "true"
	purge := c.Query("purge") == "1" || c.Query("purge") == "true"
	if de := h.svc.Delete(c.Request.Context(), c.Param("id"), userID, teardown, purge); de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict // идёт деплой: фронт вернёт проект в список и покажет подсказку
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "teardown": teardown})
}

// PATCH /api/v1/deploy/:id/settings sets the uptime check path and the Django tasks switch.
func (h *Handler) UpdateSettings(c *gin.Context) {
	userID := c.GetString("user_id")
	var body struct {
		CheckPath       string `json:"check_path"`
		SkipDjangoTasks bool   `json:"skip_django_tasks"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	view, de := h.svc.UpdateSettings(c.Request.Context(), c.Param("id"), userID, body.CheckPath, body.SkipDjangoTasks)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, view)
}

// PATCH /api/v1/deploy/:id/protection changes the protected paths and the trusted IP list.
func (h *Handler) UpdateVPNPaths(c *gin.Context) {
	userID := c.GetString("user_id")
	var body struct {
		Paths      string `json:"paths"`
		AllowedIPs string `json:"allowed_ips"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	view, de := h.svc.UpdateProtection(c.Request.Context(), c.Param("id"), userID, body.Paths, body.AllowedIPs)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, view)
}

// PATCH /api/v1/deploy/:id/team hands the project to a team (an empty team_id makes it personal).
func (h *Handler) SetProjectTeam(c *gin.Context) {
	userID := c.GetString("user_id")
	var body struct {
		TeamID string `json:"team_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	view, de := h.svc.SetProjectTeam(c.Request.Context(), c.Param("id"), userID, body.TeamID)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, view)
}

// PATCH /api/v1/deploy/:id/name sets a custom project name.
func (h *Handler) Rename(c *gin.Context) {
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	if de := h.svc.Rename(c.Request.Context(), c.Param("id"), c.GetString("user_id"), body.Name); de != nil {
		code := http.StatusUnprocessableEntity
		if de.Code == "not_found" {
			code = http.StatusNotFound
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PUT /api/v1/servers/:ip/name sets a custom server name for this user.
func (h *Handler) RenameServer(c *gin.Context) {
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	if de := h.svc.RenameServer(c.Request.Context(), c.GetString("user_id"), c.Param("ip"), body.Name); de != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/v1/servers/:ip/host-key is the "server was rebuilt" action: forget the pinned SSH
// host key so the next connection records a new one.
func (h *Handler) ResetHostKey(c *gin.Context) {
	if de := h.svc.ResetHostKey(c.Request.Context(), c.GetString("user_id"), c.Param("ip")); de != nil {
		code := http.StatusUnprocessableEntity
		if de.Code == "not_found" {
			code = http.StatusNotFound
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── server access (the user grants it themselves, we never ask for a password) ──

// accessTarget reads the ssh user from the request body (empty = root).
func accessTarget(c *gin.Context) string {
	var body struct {
		SSHUser string `json:"ssh_user"`
	}
	_ = c.ShouldBindJSON(&body)
	return body.SSHUser
}

// POST /api/v1/servers/:ip/access issues an access key (or shows the one already issued):
// the authorized_keys line plus ready-made "add" and "revoke" commands.
func (h *Handler) EnsureAccess(c *gin.Context) {
	view, de := h.svc.EnsureAccess(c.Request.Context(), c.GetString("user_id"), c.Param("ip"), accessTarget(c))
	if de != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, view)
}

// POST /api/v1/servers/:ip/access/check answers "did you add the line?" by trying the key.
func (h *Handler) CheckAccess(c *gin.Context) {
	// an access check is an ssh connect to the given IP, so it is rate limited too
	if h.tooOften(c, "access:"+c.GetString("user_id"), 30, 10*time.Minute) {
		return
	}
	res, de := h.svc.CheckAccess(c.Request.Context(), c.GetString("user_id"), c.Param("ip"), accessTarget(c))
	if de != nil {
		// "not letting us in yet" is a normal waiting answer, not a failure. 409 so the frontend
		// can tell it apart from input errors and just show a hint next to the button.
		code := http.StatusUnprocessableEntity
		if de.Code == "access_not_ready" {
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, res)
}

// DELETE /api/v1/servers/:ip/access?ssh_user=root&force=1 revokes access.
func (h *Handler) RevokeAccess(c *gin.Context) {
	res, de := h.svc.RevokeAccess(c.Request.Context(), c.GetString("user_id"), c.Param("ip"),
		c.Query("ssh_user"), c.Query("force") == "1")
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "not_found":
			code = http.StatusNotFound
		case "access_in_use", "busy":
			code = http.StatusConflict // in_use: фронт переспросит и повторит с force=1
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, res)
}

// GET /api/v1/activity?year=2026[&team_id=] returns the activity grid for a calendar year.
func (h *Handler) Activity(c *gin.Context) {
	year := 0
	if v := c.Query("year"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			year = n
		}
	}
	c.JSON(http.StatusOK, h.svc.Activity(c.Request.Context(), c.GetString("user_id"), c.Query("team_id"), year))
}

// GET /api/v1/activity/day?date=YYYY-MM-DD[&team_id=] returns what happened that day (a square click).
func (h *Handler) ActivityDay(c *gin.Context) {
	events := h.svc.ActivityDayEvents(c.Request.Context(), c.GetString("user_id"), c.Query("team_id"), c.Query("date"))
	c.JSON(http.StatusOK, gin.H{"events": events})
}

// GET /api/v1/usage lists used projects: personal (against your plan) and team (against the team plan).
func (h *Handler) Usage(c *gin.Context) {
	c.JSON(http.StatusOK, h.svc.Usage(c.Request.Context(), c.GetString("user_id")))
}

// GET /api/v1/servers lists where the user can deploy right now (access is already granted).
func (h *Handler) Servers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"servers": h.svc.Servers(c.Request.Context(), c.GetString("user_id"), c.Query("team_id"))})
}

// GET /api/v1/server-access lists every granted access: where our key sits and how to take it off.
func (h *Handler) ListAccess(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"keys": h.svc.ListAccess(c.Request.Context(), c.GetString("user_id"))})
}

// PUT /api/v1/deploy/:id/env rewrites the .env of a running project and restarts its containers.
func (h *Handler) UpdateEnv(c *gin.Context) {
	userID := c.GetString("user_id")
	var body struct {
		Env string `json:"env"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	view, de := h.svc.UpdateEnv(c.Request.Context(), c.Param("id"), userID, body.Env)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, view)
}

// GET /api/v1/deploy/:id/vpn-config returns the client WireGuard config for download.
func (h *Handler) VPNConfig(c *gin.Context) {
	userID := c.GetString("user_id")
	conf, de := h.svc.VPNConfig(c.Request.Context(), c.Param("id"), userID)
	if de != nil {
		code := http.StatusUnprocessableEntity
		switch de.Code {
		case "forbidden":
			code = http.StatusForbidden
		case "not_found":
			code = http.StatusNotFound
		case "busy":
			code = http.StatusConflict
		}
		c.JSON(code, gin.H{"error": de})
		return
	}
	c.JSON(http.StatusOK, gin.H{"config": conf})
}

// GET /api/v1/deployments returns the user's deploy history.
func (h *Handler) List(c *gin.Context) {
	userID := c.GetString("user_id")
	items, err := h.svc.List(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось загрузить историю"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deployments": items})
}

// GET /api/v1/deploy/:id returns the current state (status, steps, error, url).
func (h *Handler) Get(c *gin.Context) {
	userID := c.GetString("user_id")
	dep, err := h.svc.Find(c.Request.Context(), c.Param("id"), userID)
	if err != nil {
		notFoundOrForbidden(c, err)
		return
	}
	c.JSON(http.StatusOK, dep.View())
}

// GET /api/v1/deploy/:id/logs streams the live log over Server-Sent Events.
func (h *Handler) Logs(c *gin.Context) {
	userID := c.GetString("user_id")
	dep, err := h.svc.Find(c.Request.Context(), c.Param("id"), userID)
	if err != nil {
		notFoundOrForbidden(c, err)
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming unsupported"})
		return
	}

	ch, history := dep.Subscribe()
	defer dep.Unsubscribe(ch)

	send := func(l LogLine) {
		b, _ := json.Marshal(l)
		fmt.Fprintf(c.Writer, "data: %s\n\n", b)
		flusher.Flush()
	}

	for _, l := range history {
		send(l)
		if l.Kind == KindDone {
			return
		}
	}
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case l, ok := <-ch:
			if !ok {
				return
			}
			send(l)
			if l.Kind == KindDone {
				return
			}
		}
	}
}

func notFoundOrForbidden(c *gin.Context, err error) {
	if errors.Is(err, ErrForbidden) {
		c.JSON(http.StatusForbidden, gin.H{"error": "нет доступа к этому деплою"})
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "деплой не найден"})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "деплой не найден"})
}
