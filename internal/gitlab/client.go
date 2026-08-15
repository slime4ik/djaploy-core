// Package gitlab is a thin client for GitLab OAuth and API v4.
// BaseURL is a parameter (gitlab.com by default), groundwork for self-hosted instances.
// Read-only scopes: read_user (the login), read_api and read_repository (projects and cloning).
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Scopes are what we request during authorization. The write scope (api) is deliberately left out:
// the user adds the CD webhook themselves, and in exchange we never hold a token that can write.
const Scopes = "read_user read_api read_repository"

// httpc has a hard timeout so we never hang until the nginx timeout (like githubHTTP in auth).
var httpc = &http.Client{Timeout: 12 * time.Second}

// Token is what we store for the user (encrypted): the access token lives 2 hours,
// the refresh token rotates on every refresh.
type Token struct {
	Access    string    `json:"access"`
	Refresh   string    `json:"refresh"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the access token is due for a refresh (with a minute to spare).
func (t Token) Expired() bool {
	return time.Now().After(t.ExpiresAt.Add(-1 * time.Minute))
}

// AuthURL is where the browser is redirected for consent.
func AuthURL(baseURL, clientID, redirectURI, state string) string {
	p := url.Values{}
	p.Add("client_id", clientID)
	p.Add("redirect_uri", redirectURI)
	p.Add("response_type", "code")
	p.Add("state", state)
	p.Add("scope", Scopes)
	return strings.TrimRight(baseURL, "/") + "/oauth/authorize?" + p.Encode()
}

// ExchangeCode swaps an authorization code for a token pair.
func ExchangeCode(ctx context.Context, baseURL, clientID, clientSecret, redirectURI, code string) (Token, error) {
	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", redirectURI)
	return tokenRequest(ctx, baseURL, clientID, clientSecret, form)
}

// RefreshToken returns a fresh pair from a refresh token. IMPORTANT: the refresh rotates,
// so the returned Token must be stored in place of the old one.
func RefreshToken(ctx context.Context, baseURL, clientID, clientSecret, refresh string) (Token, error) {
	form := url.Values{}
	form.Add("grant_type", "refresh_token")
	form.Add("refresh_token", refresh)
	return tokenRequest(ctx, baseURL, clientID, clientSecret, form)
}

func tokenRequest(ctx context.Context, baseURL, clientID, clientSecret string, form url.Values) (Token, error) {
	form.Add("client_id", clientID)
	form.Add("client_secret", clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpc.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("gitlab token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("gitlab token: status %d: %s", resp.StatusCode, truncate(body))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		CreatedAt    int64  `json:"created_at"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return Token{}, fmt.Errorf("gitlab token decode: %w", err)
	}
	if tr.AccessToken == "" {
		return Token{}, fmt.Errorf("gitlab token: пустой access_token")
	}
	exp := time.Now().Add(2 * time.Hour) // дефолт GitLab, если expires_in не пришёл
	if tr.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return Token{Access: tr.AccessToken, Refresh: tr.RefreshToken, ExpiresAt: exp}, nil
}

// User is the profile used for signing in and linking.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
}

func FetchUser(ctx context.Context, baseURL, access string) (User, error) {
	var u User
	if err := getJSON(ctx, baseURL, "/api/v4/user", access, &u); err != nil {
		return User{}, err
	}
	if u.ID == 0 {
		return User{}, fmt.Errorf("gitlab user: пустой id")
	}
	return u, nil
}

// Project is shaped the way the frontend expects (the same shape as a GitHub repo).
// path_with_namespace plays the role of full_name; GitLab does not return the language
// in one call, so we leave the field out.
type Project struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	HTMLURL       string `json:"html_url"`
	Description   string `json:"description"`
	DefaultBranch string `json:"default_branch"`
	PushedAt      string `json:"pushed_at"`
	UpdatedAt     string `json:"updated_at"`
	Provider      string `json:"provider"`
}

func FetchProjects(ctx context.Context, baseURL, access string) ([]Project, error) {
	var raw []struct {
		ID                int64  `json:"id"`
		Name              string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		Visibility        string `json:"visibility"`
		WebURL            string `json:"web_url"`
		Description       string `json:"description"`
		DefaultBranch     string `json:"default_branch"`
		LastActivityAt    string `json:"last_activity_at"`
	}
	// membership=true: projects where the user is a member (personal and group ones)
	path := "/api/v4/projects?membership=true&per_page=100&order_by=last_activity_at&sort=desc&simple=true"
	if err := getJSON(ctx, baseURL, path, access, &raw); err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(raw))
	for _, p := range raw {
		out = append(out, Project{
			ID:            p.ID,
			Name:          p.Name,
			FullName:      p.PathWithNamespace,
			Private:       p.Visibility != "public",
			HTMLURL:       p.WebURL,
			Description:   p.Description,
			DefaultBranch: p.DefaultBranch,
			PushedAt:      p.LastActivityAt,
			UpdatedAt:     p.LastActivityAt,
			Provider:      "gitlab",
		})
	}
	return out, nil
}

func getJSON(ctx context.Context, baseURL, path, access string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("gitlab api %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitlab api %s: status %d: %s", path, resp.StatusCode, truncate(body))
	}
	return json.Unmarshal(body, dst)
}

// ErrUnauthorized means the access token expired or was revoked: refresh or reconnect.
var ErrUnauthorized = fmt.Errorf("gitlab: unauthorized")

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
