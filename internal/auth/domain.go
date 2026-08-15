package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User is a profile. The providers (GitHub/GitLab) are optional: 0 means not linked,
// but at least one is always there. Username/AvatarURL come from the first login provider.
type User struct {
	ID             string    `json:"-"`
	GitHubID       int64     `json:"id"` // 0 = не привязан (вход был через GitLab)
	InstallationID *int64    `json:"-"`
	Username       string    `json:"login"`
	AvatarURL      string    `json:"avatar_url"`
	GitLabID       int64     `json:"-"` // 0 = не привязан
	GitLabUsername string    `json:"gitlab_login,omitempty"`
	IsActive       bool      `json:"-"`
	CreatedAt      time.Time `json:"-"`
}

func NewUser(github_id int64, username, avatar_url string) *User {
	return &User{
		ID:        uuid.New().String(),
		GitHubID:  github_id,
		Username:  username,
		AvatarURL: avatar_url,
		IsActive:  true,
		CreatedAt: time.Now(),
	}
}

// NewUserGitLab builds a user who signed in through GitLab for the first time (github_id empty).
func NewUserGitLab(gitlabID int64, username, avatarURL string) *User {
	return &User{
		ID:             uuid.New().String(),
		GitLabID:       gitlabID,
		GitLabUsername: username,
		Username:       username,
		AvatarURL:      avatarURL,
		IsActive:       true,
		CreatedAt:      time.Now(),
	}
}

// TOKENS
// access
type AccessClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// refresh
type RefreshClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}
