package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
)

// ErrProviderTaken means this GitHub/GitLab account is already linked to another profile.
var ErrProviderTaken = errors.New("provider already linked to another user")

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) DoesUserExists(ctx context.Context, githubUserId int64) (string, error) {
	qurey := `SELECT id FROM users WHERE github_id = $1`
	var id string
	err := r.db.QueryRowContext(ctx, qurey, githubUserId).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("check user exists: %w", err)
	}
	return id, nil
}

func (r *UserRepo) CreateUser(ctx context.Context, u *User) error {
	// NULLIF(x,0): a zero provider id becomes NULL so UNIQUE does not block many users without one
	query := `INSERT INTO users (id, github_id, username, avatar_url, gitlab_id, gitlab_username, is_active, created_at)
		VALUES ($1, NULLIF($2, 0), $3, $4, NULLIF($5, 0), $6, $7, $8)`
	_, err := r.db.ExecContext(ctx, query,
		u.ID,
		u.GitHubID,
		u.Username,
		u.AvatarURL,
		u.GitLabID,
		u.GitLabUsername,
		u.IsActive,
		u.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *UserRepo) GetProfile(ctx context.Context, userID string) (*User, error) {
	query := `SELECT id, COALESCE(github_id, 0), username, avatar_url, COALESCE(gitlab_id, 0), gitlab_username, created_at
		FROM users WHERE id = $1`
	user := &User{}
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.GitHubID,
		&user.Username,
		&user.AvatarURL,
		&user.GitLabID,
		&user.GitLabUsername,
		&user.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	return user, nil
}

// GetIDByGitLabID returns a user id by gitlab_id ("" = not found), like DoesUserExists for GitHub.
func (r *UserRepo) GetIDByGitLabID(ctx context.Context, gitlabID int64) (string, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT id FROM users WHERE gitlab_id = $1`, gitlabID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get user by gitlab id: %w", err)
	}
	return id, nil
}

// AttachGitLab links GitLab to an existing profile. Taken by someone else → ErrProviderTaken.
func (r *UserRepo) AttachGitLab(ctx context.Context, userID string, gitlabID int64, username, tokenEnc string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET gitlab_id = $1, gitlab_username = $2, gitlab_token_enc = $3 WHERE id = $4`,
		gitlabID, username, tokenEnc, userID)
	if isUniqueViolation(err) {
		return ErrProviderTaken
	}
	if err != nil {
		return fmt.Errorf("attach gitlab: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// AttachGitHub links GitHub to an existing profile (the user signed in through GitLab).
func (r *UserRepo) AttachGitHub(ctx context.Context, userID string, githubID int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET github_id = $1 WHERE id = $2`, githubID, userID)
	if isUniqueViolation(err) {
		return ErrProviderTaken
	}
	if err != nil {
		return fmt.Errorf("attach github: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SaveGitLabToken updates the encrypted tokens (the refresh rotates, so we store it every time).
func (r *UserRepo) SaveGitLabToken(ctx context.Context, userID, tokenEnc string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET gitlab_token_enc = $1 WHERE id = $2`, tokenEnc, userID)
	if err != nil {
		return fmt.Errorf("save gitlab token: %w", err)
	}
	return nil
}

// GetGitLabTokenEnc returns the user's encrypted tokens ("" = GitLab is not linked).
func (r *UserRepo) GetGitLabTokenEnc(ctx context.Context, userID string) (string, error) {
	var enc string
	err := r.db.QueryRowContext(ctx,
		`SELECT gitlab_token_enc FROM users WHERE id = $1`, userID).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get gitlab token: %w", err)
	}
	return enc, nil
}

// IsActive reports whether the user is active (not banned). A cheap PK lookup. Unknown → false.
func (r *UserRepo) IsActive(ctx context.Context, userID string) (bool, error) {
	var active bool
	err := r.db.QueryRowContext(ctx, `SELECT is_active FROM users WHERE id = $1`, userID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

func (r *UserRepo) AddInstallationID(ctx context.Context, GitHubID, installationID int64) error {
	query := `UPDATE users SET installation_id = $1 WHERE github_id = $2`
	result, err := r.db.ExecContext(ctx, query, installationID, GitHubID)
	if err != nil {
		return fmt.Errorf("add installation id: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

// AddInstallationIDByUser links an installation to a user by their id (from the JWT),
// without a round trip to GitHub OAuth for the github_id.
func (r *UserRepo) AddInstallationIDByUser(ctx context.Context, userID string, installationID int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET installation_id = $1 WHERE id = $2`, installationID, userID)
	if err != nil {
		return fmt.Errorf("add installation id by user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *UserRepo) GetInstallationIDByUserID(ctx context.Context, userID string) (int64, error) {
	query := `
		SELECT installation_id 
		FROM users 
		WHERE id = $1
	`

	var installationID sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, userID).Scan(&installationID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrUserNotFound
		}

		return 0, err
	}

	if !installationID.Valid {
		return 0, ErrAppNotInstalled
	}

	return installationID.Int64, nil
}

func (r *UserRepo) ClearInstallationID(ctx context.Context, installationID int64) error {
	query := `
		UPDATE users
		SET installation_id = NULL
		WHERE installation_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, installationID)
	return err
}

func (r *UserRepo) GetUserIDFromInstallationID(ctx context.Context, installationID int64) (string, error) {
	query := `SELECT id FROM users WHERE installation_id=$1`

	var userID string

	err := r.db.QueryRowContext(ctx, query, installationID).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrUserNotFound
		}

		return "", err
	}

	return userID, nil
}
