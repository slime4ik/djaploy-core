package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/slime4ik/djaploy-core/internal/cfg"
	"github.com/slime4ik/djaploy-core/internal/crypto"
	"github.com/slime4ik/djaploy-core/internal/gitlab"
)

type UserService struct {
	repo     *UserRepo
	cfg      *cfg.Config
	oauthKey []byte // AES-ключ для GitLab-токенов в БД (соль отличает от SSH-ключей деплоя)
}

func NewUserService(repo *UserRepo, cfg *cfg.Config) *UserService {
	return &UserService{
		repo:     repo,
		cfg:      cfg,
		oauthKey: crypto.DeriveKey(cfg.JWTSecret, "djaploy-oauth"),
	}
}

func (s *UserService) CreateUser(ctx context.Context, github_id int64, username, avatar_url string) error {
	user := NewUser(github_id, username, avatar_url)
	if err := s.repo.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("ошибка создания пользователя %w", err)
	}
	return nil
}

func (s *UserService) GetUserProfile(ctx context.Context, userID string) (*User, error) {
	user, err := s.repo.GetProfile(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// IsActive reports whether the user is active (not banned through the admin is_active=false).
func (s *UserService) IsActive(ctx context.Context, userID string) (bool, error) {
	return s.repo.IsActive(ctx, userID)
}

// Returns the tokens, the userID and isNew (true = the user was just created, for the promo).
func (s *UserService) LoginOrCreateUser(ctx context.Context, githubUserID int64, username, avatarURL string) (access, refresh, userID string, isNew bool, err error) {
	userID, err = s.repo.DoesUserExists(ctx, githubUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, err
	}
	if err != nil {
		return "", "", "", false, fmt.Errorf("error finding user %w", err)
	}
	if userID == "" {
		u := NewUser(githubUserID, username, avatarURL)
		if err := s.repo.CreateUser(ctx, u); err != nil {
			return "", "", "", false, fmt.Errorf("error creating user: %w", err)
		}
		userID = u.ID
		isNew = true
	}
	// the userID is certainly there by now, for an old user and for a new one alike
	access, refresh, err = s.GenerateTokens(userID)
	if err != nil {
		return "", "", "", false, fmt.Errorf("error creating tokens for %s: %w", userID, err)
	}
	return access, refresh, userID, isNew, nil
}

// LoginOrCreateUserGitLab signs in through GitLab: find by gitlab_id or create.
// GitLab tokens are stored encrypted (they are needed for the project list and for cloning).
func (s *UserService) LoginOrCreateUserGitLab(ctx context.Context, glUser gitlab.User, tok gitlab.Token) (access, refresh, userID string, isNew bool, err error) {
	tokenEnc, err := s.encryptGitLabToken(tok)
	if err != nil {
		return "", "", "", false, fmt.Errorf("encrypt gitlab token: %w", err)
	}
	userID, err = s.repo.GetIDByGitLabID(ctx, glUser.ID)
	if err != nil {
		return "", "", "", false, fmt.Errorf("error finding user by gitlab id: %w", err)
	}
	if userID == "" {
		u := NewUserGitLab(glUser.ID, glUser.Username, glUser.AvatarURL)
		if err := s.repo.CreateUser(ctx, u); err != nil {
			return "", "", "", false, fmt.Errorf("error creating gitlab user: %w", err)
		}
		userID = u.ID
		isNew = true
	}
	if err := s.repo.SaveGitLabToken(ctx, userID, tokenEnc); err != nil {
		return "", "", "", false, err
	}
	access, refresh, err = s.GenerateTokens(userID)
	if err != nil {
		return "", "", "", false, fmt.Errorf("error creating tokens for %s: %w", userID, err)
	}
	return access, refresh, userID, isNew, nil
}

// AttachGitLab links GitLab to the current profile (from settings).
func (s *UserService) AttachGitLab(ctx context.Context, userID string, glUser gitlab.User, tok gitlab.Token) error {
	tokenEnc, err := s.encryptGitLabToken(tok)
	if err != nil {
		return fmt.Errorf("encrypt gitlab token: %w", err)
	}
	return s.repo.AttachGitLab(ctx, userID, glUser.ID, glUser.Username, tokenEnc)
}

// AttachGitHub links GitHub to a profile that was created through GitLab.
func (s *UserService) AttachGitHub(ctx context.Context, userID string, githubID int64) error {
	return s.repo.AttachGitHub(ctx, userID, githubID)
}

// GitLabToken returns a live access token: decrypt it and refresh when it expired
// (the refresh rotates, so we store the new pair). An error means GitLab is unlinked or revoked.
func (s *UserService) GitLabToken(ctx context.Context, userID string) (string, error) {
	enc, err := s.repo.GetGitLabTokenEnc(ctx, userID)
	if err != nil {
		return "", err
	}
	if enc == "" {
		return "", ErrGitLabNotConnected
	}
	plain, err := crypto.Decrypt(s.oauthKey, enc)
	if err != nil {
		return "", fmt.Errorf("decrypt gitlab token: %w", err)
	}
	var tok gitlab.Token
	if err := json.Unmarshal([]byte(plain), &tok); err != nil {
		return "", fmt.Errorf("parse gitlab token: %w", err)
	}
	if !tok.Expired() {
		return tok.Access, nil
	}
	fresh, err := gitlab.RefreshToken(ctx, s.cfg.GitLabBaseURL, s.cfg.GitLabClientID, s.cfg.GitLabClientSecret, tok.Refresh)
	if err != nil {
		return "", fmt.Errorf("refresh gitlab token: %w", err)
	}
	freshEnc, err := s.encryptGitLabToken(fresh)
	if err != nil {
		return "", fmt.Errorf("encrypt refreshed gitlab token: %w", err)
	}
	if err := s.repo.SaveGitLabToken(ctx, userID, freshEnc); err != nil {
		return "", err
	}
	return fresh.Access, nil
}

func (s *UserService) encryptGitLabToken(tok gitlab.Token) (string, error) {
	raw, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	return crypto.Encrypt(s.oauthKey, string(raw))
}

func (s *UserService) AddInstallationID(ctx context.Context, GitHubID, installation_id int64) error {
	if err := s.repo.AddInstallationID(ctx, GitHubID, installation_id); err != nil {
		return err
	}
	return nil
}

// AddInstallationIDByUser links an installation to the signed-in user (id from the JWT).
func (s *UserService) AddInstallationIDByUser(ctx context.Context, userID string, installationID int64) error {
	return s.repo.AddInstallationIDByUser(ctx, userID, installationID)
}

func (s *UserService) GenerateTokens(userID string) (access, refresh string, err error) {
	now := time.Now()

	// ACCESS: 15 minutes
	accessClaims := AccessClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	access, err = jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).
		SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", "", err
	}

	// REFRESH: 30 days, with a unique jti
	refreshClaims := RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	refresh, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).
		SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func (s *UserService) GenerateAccess(userID string) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(s.cfg.JWTSecret))
}

func (s *UserService) RefreshAccess(refreshToken string) (string, error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}
	// a banned user cannot refresh the access token (the second line after RequireActive)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if active, aerr := s.repo.IsActive(ctx, claims.UserID); aerr == nil && !active {
		return "", fmt.Errorf("user is banned")
	}
	return s.GenerateAccess(claims.UserID)
}

func (s *UserService) GetInstallationIDByUserID(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, fmt.Errorf("user id is empty")
	}

	installationID, err := s.repo.GetInstallationIDByUserID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("get installation id by user id: %w", err)
	}

	if installationID == 0 {
		return 0, fmt.Errorf("github app is not installed for user %s", userID)
	}

	return installationID, nil
}

func (s *UserService) ClearInstallationID(ctx context.Context, installatoionID int64) error {
	if err := s.repo.ClearInstallationID(ctx, installatoionID); err != nil {
		return err
	}
	return nil
}

func (s *UserService) GetUserIDFromInstallationID(ctx context.Context, installationID int64) (string, error) {
	userID, err := s.repo.GetUserIDFromInstallationID(ctx, installationID)
	if err != nil {
		return "", err
	}
	return userID, nil
}
