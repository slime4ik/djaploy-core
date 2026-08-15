package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/slime4ik/djaploy-core/internal/github"
	"github.com/slime4ik/djaploy-core/internal/gitlab"
	"github.com/slime4ik/djaploy-core/internal/store"
)

// linkCookie marks "this is linking a second provider to a profile, not a login".
// It is set by a private route (the user is already signed in) and read by the public callback.
// It cannot be forged: it is a cookie on our domain, httpOnly.
const linkCookie = "link_uid"

// PromoGranter grants the promo to a new user (implemented by *billing.Service). true = granted.
type PromoGranter interface {
	GrantNewUserMax(ctx context.Context, userID string) bool
}

// ReferralAttributor ties a new user to their referrer by code (implemented by *referral.Service).
type ReferralAttributor interface {
	Attribute(ctx context.Context, refCode, referredID string)
}

type UserHandler struct {
	s        *UserService
	cache    *store.RedisCache
	promo    PromoGranter       // опционально: акция «Max новым юзерам»
	referral ReferralAttributor // опционально: реферальная привязка по ?ref
}

func NewUserHandler(s *UserService, cache *store.RedisCache) *UserHandler {
	return &UserHandler{s: s, cache: cache}
}

// SetPromoGranter wires up the promo grant (called from main after billing is created).
func (h *UserHandler) SetPromoGranter(p PromoGranter) { h.promo = p }

// SetReferral wires up referral attribution (called from main after referral is created).
func (h *UserHandler) SetReferral(r ReferralAttributor) { h.referral = r }

// attributeReferral ties a brand new user to a referrer when the ?ref code is in the cookie.
// The cookie is set by the frontend on the landing page for a referral link; we clear it after.
func (h *UserHandler) attributeReferral(c *gin.Context, isNew bool, userID string) {
	if !isNew || h.referral == nil {
		return
	}
	if ref, err := c.Cookie("djaploy_ref"); err == nil && ref != "" {
		h.referral.Attribute(c.Request.Context(), ref, userID)
	}
	c.SetCookie("djaploy_ref", "", -1, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, false)
}

// dashboardDest decides where to send the user after signing in. A newcomer also gets new=1: the
// frontend uses it to report a signup to Metrika, because from the client a new login is otherwise
// indistinguishable from a normal one. welcome=max is the "Max for newcomers" promo, granted here.
func (h *UserHandler) dashboardDest(ctx context.Context, userID string, isNew bool) string {
	dest := h.s.cfg.FrontendURL + "/dashboard"
	if !isNew {
		return dest
	}
	q := url.Values{"new": {"1"}}
	if h.promo != nil && h.promo.GrantNewUserMax(ctx, userID) {
		q.Set("welcome", "max")
		q.Set("days", strconv.Itoa(h.s.cfg.PromoNewUserMaxDays))
	}
	return dest + "?" + q.Encode()
}

func (h *UserHandler) GitHubCallBack(c *gin.Context) {
	// 1. take code and state from the URL
	code := c.Query("code")
	githubState := c.Query("state")

	// 2. check state against the cookie
	cookieState, err := c.Cookie("state")
	if errors.Is(err, http.ErrNoCookie) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "сессия истекла, войдите снова"})
		return
	}
	if cookieState != githubState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "неверный state"})
		return // ← обязательно
	}

	// state is single use, so drop the cookie
	c.SetCookie("state", "", -1, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)

	// 3. exchange the code for a token
	form := url.Values{}
	form.Add("client_id", h.s.cfg.GitHubClientID)
	form.Add("client_secret", h.s.cfg.GitHubClientSecret)
	form.Add("code", code)

	req, err := http.NewRequest(
		http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := githubHTTP.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "github unreachable"})
		return
	}
	defer resp.Body.Close()

	// 4. parse the response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bad github response"})
		return
	}
	// Parse the user profile
	req, _ = http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	req.Header.Set("User-Agent", "djaploy")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err = githubHTTP.Do(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "github error"})
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "github returned error"})
		return
	}
	defer resp.Body.Close()
	var userResponse struct {
		GitHubID  int64  `json:"id"`
		AvatarURL string `json:"avatar_url"`
		Username  string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bad github response"})
		return
	}
	// link mode: the user signed in through GitLab and is attaching GitHub to their profile
	if linkUID, lerr := c.Cookie(linkCookie); lerr == nil && linkUID != "" {
		c.SetCookie(linkCookie, "", -1, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
		dest := h.s.cfg.FrontendURL + "/settings"
		if err := h.s.AttachGitHub(c.Request.Context(), linkUID, userResponse.GitHubID); err != nil {
			if errors.Is(err, ErrProviderTaken) {
				c.Redirect(http.StatusFound, dest+"?error=github_taken")
				return
			}
			log.Printf("attach github to %s failed: %v", linkUID, err)
			c.Redirect(http.StatusFound, dest+"?error=link_failed")
			return
		}
		c.Redirect(http.StatusFound, dest+"?linked=github")
		return
	}

	// GENERATE tokens VIA LoginOrCreateUser
	access, refresh, userID, isNew, err := h.s.LoginOrCreateUser(c.Request.Context(), userResponse.GitHubID, userResponse.Username, userResponse.AvatarURL)
	if err != nil {
		log.Printf("login failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось войти"})
		return
	}
	// SET tokens INTO cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", access, 15*60, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)        // 15 мин
	c.SetCookie("refresh_token", refresh, 30*24*3600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true) // 30 дней

	h.attributeReferral(c, isNew, userID) // реферальная привязка по ?ref-куке (если новый)

	// promo: a new user gets Max → the dashboard shows a welcome box (?welcome=max&days=N)
	c.Redirect(http.StatusFound, h.dashboardDest(c.Request.Context(), userID, isNew))
}

// DemoLogin is the secret sign-in for YooKassa moderators (no GitHub).
// GET /api/v1/auth/demo?code=SECRET sets a demo user session and redirects to the dashboard.
// The demo user has no GitHub link: they see all the content and plans but cannot deploy.
const demoGitHubID int64 = 100000000001 // зарезервированный фейковый github_id для демо

func (h *UserHandler) DemoLogin(c *gin.Context) {
	if h.s.cfg.DemoCode == "" || c.Query("code") != h.s.cfg.DemoCode {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "нет доступа"})
		return
	}
	access, refresh, _, _, err := h.s.LoginOrCreateUser(c.Request.Context(), demoGitHubID, "demo-yookassa", "")
	if err != nil {
		log.Printf("demo login failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось войти"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", access, 15*60, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	c.SetCookie("refresh_token", refresh, 30*24*3600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	c.Redirect(http.StatusFound, h.s.cfg.FrontendURL+"/dashboard")
}

func (h *UserHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no refresh token"})
		return
	}
	access, err := h.s.RefreshAccess(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", access, 15*60, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *UserHandler) GitHubAuth(c *gin.Context) {
	state := uuid.NewString()
	c.SetCookie("state", state, 3600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)

	params := url.Values{}
	params.Add("client_id", h.s.cfg.GitHubClientID)
	params.Add("redirect_uri", h.s.cfg.PublicURL+"/api/v1/auth/callback")
	params.Add("scope", "read:user")
	params.Add("state", state)

	redirectURL := "https://github.com/login/oauth/authorize?" + params.Encode()

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// ── GitLab OAuth ──────────────────────────────────────────────

// Providers reports which sign-in methods are available (for the login page, public).
func (h *UserHandler) Providers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"github": true,
		"gitlab": h.s.cfg.GitLabEnabled(),
	})
}

// gitLabRedirect is the shared part: the state cookie plus a redirect to the GitLab consent screen.
func (h *UserHandler) gitLabRedirect(c *gin.Context) {
	state := uuid.NewString()
	c.SetCookie("state", state, 3600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	c.Redirect(http.StatusTemporaryRedirect, gitlab.AuthURL(
		h.s.cfg.GitLabBaseURL,
		h.s.cfg.GitLabClientID,
		h.s.cfg.PublicURL+"/api/v1/auth/gitlab/callback",
		state,
	))
}

// GitLabAuth signs in through GitLab (public).
func (h *UserHandler) GitLabAuth(c *gin.Context) {
	if !h.s.cfg.GitLabEnabled() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "вход через GitLab не настроен"})
		return
	}
	// in case a link flow was started earlier, this is a clean login
	c.SetCookie(linkCookie, "", -1, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	h.gitLabRedirect(c)
}

// GitLabLink attaches GitLab to the current profile (private: the user is already signed in).
func (h *UserHandler) GitLabLink(c *gin.Context) {
	if !h.s.cfg.GitLabEnabled() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "GitLab не настроен"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "не авторизован"})
		return
	}
	c.SetCookie(linkCookie, userID, 600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	h.gitLabRedirect(c)
}

// GitHubLink attaches GitHub to a profile created through GitLab (private).
func (h *UserHandler) GitHubLink(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "не авторизован"})
		return
	}
	c.SetCookie(linkCookie, userID, 600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	h.GitHubAuth(c)
}

// GitLabCallback is the GitLab callback: a login OR a link (decided by the link cookie).
func (h *UserHandler) GitLabCallback(c *gin.Context) {
	if !h.s.cfg.GitLabEnabled() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "GitLab не настроен"})
		return
	}
	code, glState := c.Query("code"), c.Query("state")
	cookieState, err := c.Cookie("state")
	if errors.Is(err, http.ErrNoCookie) || cookieState != glState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "сессия истекла, войдите снова"})
		return
	}
	c.SetCookie("state", "", -1, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)

	ctx := c.Request.Context()
	tok, err := gitlab.ExchangeCode(ctx, h.s.cfg.GitLabBaseURL, h.s.cfg.GitLabClientID,
		h.s.cfg.GitLabClientSecret, h.s.cfg.PublicURL+"/api/v1/auth/gitlab/callback", code)
	if err != nil {
		log.Printf("gitlab exchange failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "GitLab недоступен — попробуй ещё раз"})
		return
	}
	glUser, err := gitlab.FetchUser(ctx, h.s.cfg.GitLabBaseURL, tok.Access)
	if err != nil {
		log.Printf("gitlab user fetch failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "GitLab недоступен — попробуй ещё раз"})
		return
	}

	// link mode: the user is already signed in, we just attach GitLab to their profile
	if linkUID, lerr := c.Cookie(linkCookie); lerr == nil && linkUID != "" {
		c.SetCookie(linkCookie, "", -1, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
		dest := h.s.cfg.FrontendURL + "/settings"
		if err := h.s.AttachGitLab(ctx, linkUID, glUser, tok); err != nil {
			if errors.Is(err, ErrProviderTaken) {
				c.Redirect(http.StatusFound, dest+"?error=gitlab_taken")
				return
			}
			log.Printf("attach gitlab to %s failed: %v", linkUID, err)
			c.Redirect(http.StatusFound, dest+"?error=link_failed")
			return
		}
		c.Redirect(http.StatusFound, dest+"?linked=gitlab")
		return
	}

	// a normal sign-in
	access, refresh, userID, isNew, err := h.s.LoginOrCreateUserGitLab(ctx, glUser, tok)
	if err != nil {
		log.Printf("gitlab login failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось войти"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", access, 15*60, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)
	c.SetCookie("refresh_token", refresh, 30*24*3600, "/", h.s.cfg.CookieDomain, h.s.cfg.CookieSecure, true)

	h.attributeReferral(c, isNew, userID) // реферальная привязка по ?ref-куке (если новый)

	c.Redirect(http.StatusFound, h.dashboardDest(ctx, userID, isNew))
}

func (h *UserHandler) GetUserProfile(c *gin.Context) {
	// get user_id from jwt middleware
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "не авторизован"})
		return
	}
	// get profile data
	user, err := h.s.GetUserProfile(c.Request.Context(), userID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrUserNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "пользователя с таким id нету"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось получить профиль"})
		return
	}
	// login and avatar come from the first login provider; providers lists what is attached
	c.JSON(http.StatusOK, gin.H{
		"id":           user.GitHubID,
		"login":        user.Username,
		"avatar_url":   user.AvatarURL,
		"gitlab_login": user.GitLabUsername,
		"providers": gin.H{
			"github": user.GitHubID != 0,
			"gitlab": user.GitLabID != 0,
		},
		"gitlab_available": h.s.cfg.GitLabEnabled(),
	})
}

func (h *UserHandler) GitHubAppCallback(c *gin.Context) {
	dashboard := h.s.cfg.FrontendURL + "/dashboard"

	// The route is private (behind JWT), so we already know from the token who is installing the App.
	// That is why we do NOT go to GitHub OAuth for the github_id (which is what used to hang the
	// callback into a 504), we attach the installation to the current user directly.
	userID := c.GetString("user_id")
	installationID, err := strconv.ParseInt(c.Query("installation_id"), 10, 64)
	if userID == "" || err != nil || installationID == 0 {
		c.Redirect(http.StatusFound, dashboard)
		return
	}

	if err := h.s.AddInstallationIDByUser(c.Request.Context(), userID, installationID); err != nil {
		log.Printf("link installation to user %s failed: %v", userID, err)
		c.Redirect(http.StatusFound, dashboard)
		return
	}

	// Warm the installation token in the cache when we can. If it fails (GitHub being slow) it does
	// not matter: /repos will issue one on demand. What matters is that the installation is linked.
	if token, terr := github.InstallationToken(h.s.cfg.GitHunAppID, h.s.cfg.GitHubAppPemPath, installationID); terr == nil {
		_ = h.cache.SetInstallationToken(c.Request.Context(), userID, token)
	} else {
		log.Printf("prewarm installation token failed (non-fatal): %v", terr)
	}

	c.Redirect(http.StatusFound, dashboard)
}

// HELPERS
func (h *UserHandler) getOrCreateInstallationToken(ctx context.Context, userID string) (string, error) {
	token, err := h.cache.GetInstallationToken(ctx, userID)
	if err == nil {
		return token, nil
	}

	installationID, err := h.s.GetInstallationIDByUserID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("get installation id: %w", err)
	}

	token, err = github.InstallationToken(
		h.s.cfg.GitHunAppID,
		h.s.cfg.GitHubAppPemPath,
		installationID,
	)
	if err != nil {
		// the installation was deleted or revoked on GitHub → clear the dead id and treat it as "not connected"
		if errors.Is(err, github.ErrInstallationGone) {
			h.forgetInstallation(ctx, userID, installationID)
			return "", ErrAppNotInstalled
		}
		return "", fmt.Errorf("create installation token: %w", err)
	}

	if err := h.cache.SetInstallationToken(ctx, userID, token); err != nil {
		return "", fmt.Errorf("cache installation token: %w", err)
	}

	return token, nil
}

// forgetInstallation clears a dead installation (self healing when the installation.deleted
// webhook never arrived): it drops installation_id from the database and the token from the cache.
func (h *UserHandler) forgetInstallation(ctx context.Context, userID string, installationID int64) {
	if err := h.s.ClearInstallationID(ctx, installationID); err != nil {
		log.Printf("self-heal: clear installation %d failed: %v", installationID, err)
	}
	_ = h.cache.DeleteInstallationToken(ctx, userID)
}

func (h *UserHandler) refreshInstallationToken(ctx context.Context, userID string) (string, error) {
	_ = h.cache.DeleteInstallationToken(ctx, userID)

	installationID, err := h.s.GetInstallationIDByUserID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("get installation id: %w", err)
	}

	token, err := github.InstallationToken(
		h.s.cfg.GitHunAppID,
		h.s.cfg.GitHubAppPemPath,
		installationID,
	)
	if err != nil {
		if errors.Is(err, github.ErrInstallationGone) {
			h.forgetInstallation(ctx, userID, installationID)
			return "", ErrAppNotInstalled
		}
		return "", fmt.Errorf("refresh installation token: %w", err)
	}

	if err := h.cache.SetInstallationToken(ctx, userID, token); err != nil {
		return "", fmt.Errorf("cache refreshed installation token: %w", err)
	}

	return token, nil
}

// githubHTTP is a separate client with a hard timeout so a request to GitHub never hangs until the
// nginx timeout (60s). Returning a clear error quickly is better.
var githubHTTP = &http.Client{Timeout: 12 * time.Second}

func (h *UserHandler) fetchInstallationRepos(ctx context.Context, token string) ([]byte, int, error) {
	// an independent deadline for the request: we do not depend on the browser or nginx giving up
	rctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	_ = ctx // совместимость сигнатуры

	req, err := http.NewRequestWithContext(
		rctx,
		http.MethodGet,
		"https://api.github.com/installation/repositories?per_page=100",
		nil,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("create github repos request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "djaploy")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := githubHTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("do github repos request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read github repos response: %w", err)
	}

	return body, resp.StatusCode, nil
}

func (h *UserHandler) GetUserRepos(c *gin.Context) {
	ctx := c.Request.Context()

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	token, err := h.getOrCreateInstallationToken(ctx, userID)
	if errors.Is(err, ErrAppNotInstalled) || errors.Is(err, ErrUserNotFound) {
		c.JSON(http.StatusOK, gin.H{"connected": false, "repositories": []any{}})
		return
	}
	if err != nil {
		log.Printf("get installation token failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось получить github token"})
		return
	}

	body, statusCode, err := h.fetchInstallationRepos(ctx, token)
	if err != nil {
		log.Printf("github repos request failed: %v", err)
		// GitHub is unreachable or timing out (common from a Russian server) → serve the last known
		// list so the dashboard does not fall over because of a network blip.
		if cached, cErr := h.cache.GetReposCache(ctx, userID); cErr == nil && len(cached) > 0 {
			log.Printf("repos: GitHub недоступен — отдаю кэш для %s", userID)
			c.Data(http.StatusOK, "application/json; charset=utf-8", cached)
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "GitHub временно недоступен — попробуй обновить через пару секунд.",
		})
		return
	}

	if statusCode == http.StatusUnauthorized {
		token, err = h.refreshInstallationToken(ctx, userID)
		if err != nil {
			// 401 plus a failed refresh means the app was revoked or deleted, not a server error
			log.Printf("refresh after 401 failed (treat as disconnected): %v", err)
			c.JSON(http.StatusOK, gin.H{"connected": false, "repositories": []any{}}) // ← вместо 500
			return
		}

		body, statusCode, err = h.fetchInstallationRepos(ctx, token)
		if err != nil {
			log.Printf("github repos retry failed: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "github error"})
			return
		}
	}

	if statusCode != http.StatusOK {
		log.Printf("github returned status %d: %s", statusCode, string(body))
		c.JSON(statusCode, gin.H{"error": "github returned error"})
		return
	}

	var reposResp struct {
		TotalCount   int `json:"total_count"`
		Repositories []struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			FullName    string `json:"full_name"`
			Private     bool   `json:"private"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
			Language    string `json:"language"`
			PushedAt    string `json:"pushed_at"`
			UpdatedAt   string `json:"updated_at"`
		} `json:"repositories"`
	}

	if err := json.Unmarshal(body, &reposResp); err != nil {
		log.Printf("decode github repos failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bad github response"})
		return
	}

	// sort by the last push date (newest first) so fresh repositories are on top
	sort.Slice(reposResp.Repositories, func(i, j int) bool {
		ti := reposResp.Repositories[i].PushedAt
		if ti == "" {
			ti = reposResp.Repositories[i].UpdatedAt
		}
		tj := reposResp.Repositories[j].PushedAt
		if tj == "" {
			tj = reposResp.Repositories[j].UpdatedAt
		}
		return ti > tj // ISO-8601 строки сравниваются лексикографически = хронологически
	})

	resp := gin.H{
		"total_count":  reposResp.TotalCount,
		"repositories": reposResp.Repositories,
	}
	// cache the successful list: we will serve it if GitHub goes away for a while later
	if data, mErr := json.Marshal(resp); mErr == nil {
		_ = h.cache.SetReposCache(ctx, userID, data)
	}
	c.JSON(http.StatusOK, resp)
}

// GetGitLabRepos returns the user's GitLab projects. The response is shaped like /repos:
// {connected, repositories[]}, and the frontend merges the lists itself.
func (h *UserHandler) GetGitLabRepos(c *gin.Context) {
	notConnected := gin.H{"connected": false, "repositories": []any{}}
	if !h.s.cfg.GitLabEnabled() {
		c.JSON(http.StatusOK, notConnected)
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}
	ctx := c.Request.Context()
	token, err := h.s.GitLabToken(ctx, userID)
	if errors.Is(err, ErrGitLabNotConnected) || errors.Is(err, ErrUserNotFound) {
		c.JSON(http.StatusOK, notConnected)
		return
	}
	if err != nil {
		// the refresh was rejected by GitLab (the user revoked access) → "not connected", can be linked again;
		// a network failure → an honest 503, the frontend shows "try later"
		if strings.Contains(err.Error(), "status 400") || strings.Contains(err.Error(), "status 401") {
			log.Printf("gitlab token revoked for %s: %v", userID, err)
			c.JSON(http.StatusOK, notConnected)
			return
		}
		log.Printf("gitlab token failed for %s: %v", userID, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GitLab временно недоступен — попробуй обновить через пару секунд."})
		return
	}
	projects, err := gitlab.FetchProjects(ctx, h.s.cfg.GitLabBaseURL, token)
	if errors.Is(err, gitlab.ErrUnauthorized) {
		// the token is fresh but GitLab did not accept it, so access was revoked
		c.JSON(http.StatusOK, notConnected)
		return
	}
	if err != nil {
		log.Printf("gitlab projects failed for %s: %v", userID, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GitLab временно недоступен — попробуй обновить через пару секунд."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"connected": true, "repositories": projects})
}

func (h *UserHandler) GitHubAppWebHook(c *gin.Context) {
	event := c.GetHeader("X-GitHub-Event")
	signature := c.GetHeader("X-Hub-Signature-256")
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	if !validGitHubSignature(signature, body, h.s.cfg.GitHubAppWebHookSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad signature"})
		return
	}
	if event != "installation" {
		c.JSON(http.StatusOK, gin.H{"status": "ignored"})
		return
	}
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}
	if payload.Action != "deleted" {
		c.JSON(http.StatusOK, gin.H{"status": "ignored"})
		return
	}
	installationID := payload.Installation.ID
	// clear cache
	userID, err := h.s.GetUserIDFromInstallationID(c.Request.Context(), installationID)
	if err != nil {
		log.Printf("ошибка очистки кэша %v", err)
	}
	if err := h.cache.DeleteInstallationToken(c.Request.Context(), userID); err != nil {
		log.Printf("ошибка очистки кэша %v", err)
	}
	// Remove installation_id from user
	if err := h.s.ClearInstallationID(c.Request.Context(), installationID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "clear_installation_id_failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":          "deleted received",
		"installation_id": installationID,
	})
}

func validGitHubSignature(signatureHeader string, body []byte, secret string) bool {

	const prefix = "sha256="
	if signatureHeader == "" || secret == "" {
		return false
	}
	if !strings.HasPrefix(signatureHeader, prefix) {
		return false
	}
	gotHex := strings.TrimPrefix(signatureHeader, prefix)
	got, err := hex.DecodeString(gotHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(got, expected)

}
