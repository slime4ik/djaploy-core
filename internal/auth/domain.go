package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User is the profile. The providers (GitHub and GitLab) are optional, 0 means not attached, and
// at least one of them is always present. Username and AvatarURL come from the provider of the
// first sign-in.
type User struct {
	ID             string    `json:"-"`
	GitHubID       int64     `json:"id"` // 0 means not attached (the user signed in through GitLab)
	InstallationID *int64    `json:"-"`
	Username       string    `json:"login"`
	AvatarURL      string    `json:"avatar_url"`
	GitLabID       int64     `json:"-"` // 0 means not attached
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

// NewUserGitLab is a user whose first sign-in was through GitLab, so github_id stays empty.
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
