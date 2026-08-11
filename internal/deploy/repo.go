package deploy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Repo persists deploys in Postgres: history plus recovery after a page refresh or a restart.
// No secrets are stored here, only metadata, steps, the error, the url and the logs.
type Repo struct{ db *sql.DB }

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

func (r *Repo) Create(ctx context.Context, d *Deployment) error {
	steps, _ := json.Marshal(d.Steps)
	const q = `
		INSERT INTO deployments
			(id, user_id, team_id, repo, provider, domain, server_ip, app_service, app_port,
			 serve_static, serve_media, static_volume, media_volume, status, steps, ssh_user, cd_enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())`
	_, err := r.db.ExecContext(ctx, q,
		d.ID, d.UserID, nullStr(d.TeamID), d.Repo, providerOrDefault(d.Provider), d.Domain, d.ServerIP, d.AppService, d.AppPort,
		d.ServeStatic, d.ServeMedia, d.StaticVolume, d.MediaVolume, d.Status, steps, d.SSHUser, d.CDEnabled, d.CreatedAt)
	if err != nil {
		return fmt.Errorf("create deployment: %w", err)
	}
	return nil
}

// UsedHostPorts returns the host ports (app and grafana) already claimed by OTHER deploys on this
// server, so a new site never hands itself a neighbour's port even before that port is bound.
func (r *Repo) UsedHostPorts(ctx context.Context, serverIP, excludeID string) []int {
	rows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(NULLIF(server_state->>'host_port','')::int, 0),
		       COALESCE(NULLIF(server_state->>'grafana_port','')::int, 0)
		FROM deployments WHERE server_ip=$1 AND id <> $2`, serverIP, excludeID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var hp, gp int
		if err := rows.Scan(&hp, &gp); err != nil {
			continue
		}
		if hp > 0 {
			out = append(out, hp)
		}
		if gp > 0 {
			out = append(out, gp)
		}
	}
	return out
}

// DomainInUse reports whether the domain is taken by another ACTIVE deploy of this user, which
// guards against a duplicate domain and the gateway and certificate conflict that follows. It
// returns the name or repo of the project holding it. excludeID is the current deploy, so a
// redeploy does not count itself; pass "" for a new one.
func (r *Repo) DomainInUse(ctx context.Context, domain, userID, excludeID string) (string, bool) {
	var repo, name string
	err := r.db.QueryRowContext(ctx, `
		SELECT repo, COALESCE(name,'') FROM deployments
		WHERE lower(domain)=lower($1) AND user_id=$2 AND id <> $3 AND status <> 'failed'
		LIMIT 1`, strings.TrimSpace(domain), userID, excludeID).Scan(&repo, &name)
	if err != nil {
		return "", false
	}
	if name != "" {
		return name, true
	}
	return repo, true
}

// RepoOnServer reports whether this repository is ALREADY deployed on this server for the same
// user. It matters because the directory, the containers and the gateway snippet are all keyed by
// repo name, so a second deploy of the same repo onto the same server would overwrite the first.
// It returns the name or domain of the project holding it.
func (r *Repo) RepoOnServer(ctx context.Context, repo, serverIP, userID, excludeID string) (string, bool) {
	var domain, name string
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(domain,''), COALESCE(name,'') FROM deployments
		WHERE repo=$1 AND server_ip=$2 AND user_id=$3 AND id <> $4 AND status <> 'failed'
		LIMIT 1`, repo, strings.TrimSpace(serverIP), userID, excludeID).Scan(&domain, &name)
	if err != nil {
		return "", false
	}
	switch {
	case name != "":
		return name, true
	case domain != "":
		return domain, true
	default:
		return repo, true
	}
}

// SetNameByID sets a custom project name. Access is checked in the service layer (owner or team
// member), so this one works by id alone.
func (r *Repo) SetNameByID(ctx context.Context, id, name string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE deployments SET name=$2, updated_at=NOW() WHERE id=$1`, id, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetServerLabel sets or updates a custom server name for a user (the user plus IP pair).
func (r *Repo) SetServerLabel(ctx context.Context, userID, ip, name string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO server_labels (user_id, server_ip, name) VALUES ($1,$2,$3)
		ON CONFLICT (user_id, server_ip) DO UPDATE SET name=EXCLUDED.name`, userID, ip, name)
	return err
}

// HostPin returns the pinned host key for a user and IP. ok=false means the server is not known yet.
func (r *Repo) HostPin(ctx context.Context, userID, ip string) (fp, keyType string, ok bool) {
	err := r.db.QueryRowContext(ctx,
		`SELECT fingerprint, key_type FROM server_host_keys WHERE user_id=$1 AND server_ip=$2`,
		userID, strings.TrimSpace(ip)).Scan(&fp, &keyType)
	if err != nil {
		return "", "", false
	}
	return fp, keyType, fp != ""
}

// TrustHostPin is an atomic get-or-create: it writes our row when none exists and returns the
// already stored one otherwise. Two simultaneous first connections to one IP therefore cannot
// overwrite each other, and the loser has to compare the returned fingerprint against its own.
func (r *Repo) TrustHostPin(ctx context.Context, userID, ip, fp, keyType, pubkey string) (string, error) {
	var stored string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO server_host_keys (user_id, server_ip, key_type, fingerprint, pubkey)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (user_id, server_ip) DO UPDATE SET last_seen=NOW()
		RETURNING fingerprint`,
		userID, strings.TrimSpace(ip), keyType, fp, pubkey).Scan(&stored)
	return stored, err
}

// TouchHostPin records that the key matched today. Best effort, the error is ignored.
func (r *Repo) TouchHostPin(ctx context.Context, userID, ip string) {
	_, _ = r.db.ExecContext(ctx,
		`UPDATE server_host_keys SET last_seen=NOW() WHERE user_id=$1 AND server_ip=$2`,
		userID, strings.TrimSpace(ip))
}

// ForgetHostPin drops the fingerprint (the server was rebuilt). The next connection records a new one.
func (r *Repo) ForgetHostPin(ctx context.Context, userID, ip string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM server_host_keys WHERE user_id=$1 AND server_ip=$2`,
		userID, strings.TrimSpace(ip))
	return err
}

// HasDeploymentsOn reports whether the user still has projects on this server. The pin dies with
// the last one, otherwise the user would be left with no server card to reset it from.
func (r *Repo) HasDeploymentsOn(ctx context.Context, userID, ip string) bool {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM deployments WHERE user_id=$1 AND server_ip=$2`,
		userID, strings.TrimSpace(ip)).Scan(&n)
	return err == nil && n > 0
}

// SaveSSHKey stores the encrypted access key used for password-less redeploys and CD.
func (r *Repo) SaveSSHKey(ctx context.Context, id, enc string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE deployments SET ssh_key_enc=$2, updated_at=NOW() WHERE id=$1`, id, enc)
	return err
}

// SetHealth records the live health of a site (up|down|""). The uptime monitor writes it, and a
// redeploy resets it to "" (unknown) so a stale "down" is not shown during a rebuild.
func (r *Repo) SetHealth(ctx context.Context, id, health string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE deployments SET health=$2 WHERE id=$1`, id, health)
	return err
}

// SetCDByID turns auto deploy on git push on or off. Access is checked in the service layer
// (owner or team member).
func (r *Repo) SetCDByID(ctx context.Context, id string, enabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE deployments SET cd_enabled=$2, updated_at=NOW() WHERE id=$1`, id, enabled)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// LatestCDByRepo returns the newest deploy with CD enabled for a repository and provider. The
// push webhook needs it, and github and gitlab post to different routes.
func (r *Repo) LatestCDByRepo(ctx context.Context, repo, provider string) (*Deployment, string, error) {
	const q = `
		SELECT id FROM deployments
		WHERE repo=$1 AND provider=$2 AND cd_enabled=TRUE AND ssh_key_enc IS NOT NULL
		ORDER BY created_at DESC LIMIT 1`
	var id string
	if err := r.db.QueryRowContext(ctx, q, repo, providerOrDefault(provider)).Scan(&id); err != nil {
		return nil, "", err
	}
	return r.getFull(ctx, id)
}

// SaveState updates status, steps, error and url. It skips the logs because it is called often.
func (r *Repo) SaveState(ctx context.Context, d *Deployment) error {
	steps, _ := json.Marshal(d.Steps)
	var errJSON []byte
	if d.Err != nil {
		errJSON, _ = json.Marshal(d.Err)
	}
	state, _ := json.Marshal(d.ServerState)
	const q = `
		UPDATE deployments
		SET status=$2, steps=$3, error=$4, url=$5, server_state=$6, ssh_user=$7, updated_at=NOW()
		WHERE id=$1`
	_, err := r.db.ExecContext(ctx, q, d.ID, d.Status, steps, nullJSON(errJSON), nullStr(d.URL), state, d.SSHUser)
	return err
}

// SaveFinal does the same and adds the logs, on a terminal status.
func (r *Repo) SaveFinal(ctx context.Context, d *Deployment) error {
	steps, _ := json.Marshal(d.Steps)
	var errJSON []byte
	if d.Err != nil {
		errJSON, _ = json.Marshal(d.Err)
	}
	logs, _ := json.Marshal(d.LogsSnapshot())
	state, _ := json.Marshal(d.ServerState)
	const q = `
		UPDATE deployments
		SET status=$2, steps=$3, error=$4, url=$5, logs=$6, server_state=$7, ssh_user=$8, updated_at=NOW()
		WHERE id=$1`
	_, err := r.db.ExecContext(ctx, q, d.ID, d.Status, steps, nullJSON(errJSON), nullStr(d.URL), logs, state, d.SSHUser)
	return err
}

// Get loads a finished deploy from the database, for history or after a restart.
// It comes back with done=true and restored logs, so Subscribe replays them and closes the stream.
func (r *Repo) Get(ctx context.Context, id string) (*Deployment, error) {
	d, _, err := r.getFull(ctx, id)
	return d, err
}

// getFull is Get plus the ENCRYPTED access key, which redeploy and CD need. The key never leaves
// through View.
func (r *Repo) getFull(ctx context.Context, id string) (*Deployment, string, error) {
	const q = `
		SELECT id, user_id, team_id, repo, provider, name, domain, server_ip, app_service, app_port,
		       serve_static, serve_media, static_volume, media_volume, status, health, steps, error, url, logs,
		       ssh_user, cd_enabled, ssh_key_enc, server_state, created_at
		FROM deployments WHERE id=$1`
	var (
		d                                   Deployment
		steps, errJSON, logsJSON, stateJSON []byte
		url, keyEnc, teamID                 sql.NullString
	)
	err := r.db.QueryRowContext(ctx, q, id).Scan(
		&d.ID, &d.UserID, &teamID, &d.Repo, &d.Provider, &d.Name, &d.Domain, &d.ServerIP, &d.AppService, &d.AppPort,
		&d.ServeStatic, &d.ServeMedia, &d.StaticVolume, &d.MediaVolume, &d.Status, &d.Health, &steps, &errJSON, &url, &logsJSON,
		&d.SSHUser, &d.CDEnabled, &keyEnc, &stateJSON, &d.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	d.TeamID = teamID.String
	_ = json.Unmarshal(steps, &d.Steps)
	if len(stateJSON) > 0 {
		_ = json.Unmarshal(stateJSON, &d.ServerState)
	}
	if len(errJSON) > 0 {
		d.Err = &DeployError{}
		_ = json.Unmarshal(errJSON, d.Err)
	}
	if url.Valid {
		d.URL = url.String
	}
	if len(logsJSON) > 0 {
		_ = json.Unmarshal(logsJSON, &d.logs)
	}
	if keyEnc.Valid {
		d.sshKeyEnc = keyEnc.String
	}
	d.done = true
	return &d, keyEnc.String, nil
}

// DeploymentSummary is the short record for the history list (no logs and no mutex).
type DeploymentSummary struct {
	ID         string `json:"id"`
	Repo       string `json:"repo"`
	Provider   string `json:"provider"`
	Name       string `json:"name"` // custom project name (empty means domain or repo)
	Domain     string `json:"domain"`
	ServerIP   string `json:"server_ip"`   // used to group projects by server in the dashboard
	ServerName string `json:"server_name"` // custom server name (empty means the IP)
	Status     string `json:"status"`
	Health     string `json:"health"` // up|down|"": live health of the site from the uptime monitor
	URL        string `json:"url,omitempty"`
	TeamID     string `json:"team_id,omitempty"` // non-empty means a team project
	Mine       bool   `json:"mine"`              // whether the caller owns the row, so the UI can mark team projects
	CreatedAt  string `json:"created_at"`
}

// ListVisible returns the user's own deploys plus the projects of their teams.
func (r *Repo) ListVisible(ctx context.Context, userID string, teamIDs []string, limit int) ([]DeploymentSummary, error) {
	// own rows OR rows from the user's teams; the LEFT JOIN pulls the custom server name per user and IP.
	q := `SELECT d.id, d.user_id, d.team_id, d.repo, d.provider, d.name, d.domain, d.server_ip,
		       COALESCE(sl.name,''), d.status, d.health, d.url, d.created_at
		FROM deployments d
		LEFT JOIN server_labels sl ON sl.user_id=$1 AND sl.server_ip=d.server_ip
		WHERE ((d.user_id=$1 AND d.team_id IS NULL)`
	args := []any{userID}
	for i, tid := range teamIDs {
		q += fmt.Sprintf(" OR d.team_id=$%d", i+2)
		args = append(args, tid)
	}
	q += fmt.Sprintf(") ORDER BY d.created_at DESC LIMIT %d", limit)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeploymentSummary{}
	for rows.Next() {
		var s DeploymentSummary
		var url, teamID sql.NullString
		var owner string
		var created time.Time
		if err := rows.Scan(&s.ID, &owner, &teamID, &s.Repo, &s.Provider, &s.Name, &s.Domain, &s.ServerIP, &s.ServerName, &s.Status, &s.Health, &url, &created); err != nil {
			return nil, err
		}
		s.URL = url.String
		s.TeamID = teamID.String
		s.Mine = owner == userID
		s.CreatedAt = created.Format(time.RFC3339)
		out = append(out, s)
	}
	return out, rows.Err()
}

// CountActiveByUser counts the user's active personal projects. Team projects and failed ones do not count.
func (r *Repo) CountActiveByUser(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM deployments WHERE user_id=$1 AND team_id IS NULL AND status <> 'failed'`, userID).Scan(&n)
	return n, err
}

// SetTeam attaches a project to a team (an empty teamID makes it personal again).
func (r *Repo) SetTeam(ctx context.Context, id, teamID string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE deployments SET team_id=$2, updated_at=NOW() WHERE id=$1`, id, nullStr(teamID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountActiveByTeam counts a team's active projects, which the team plan limit uses.
func (r *Repo) CountActiveByTeam(ctx context.Context, teamID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM deployments WHERE team_id=$1 AND status <> 'failed'`, teamID).Scan(&n)
	return n, err
}

// DeleteFailedTarget removes FAILED attempts for the same repo, provider and server of this user,
// so a repeated deploy does not pile up broken rows. It returns the deleted ids, which the caller
// also drops from the in-memory store. Successful and running deploys are left alone.
func (r *Repo) DeleteFailedTarget(ctx context.Context, userID, repo, provider, serverIP string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`DELETE FROM deployments
		 WHERE user_id=$1 AND repo=$2 AND provider=$3 AND server_ip=$4 AND status='failed'
		 RETURNING id`,
		userID, repo, providerOrDefault(provider), strings.TrimSpace(serverIP))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Delete removes the project row, which unlinks it from our service. Access is checked in the
// service layer (owner or team member), so this one works by id alone.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM deployments WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// MarkOrphans marks deploys left hanging in running or queued as failed when the server starts.
func (r *Repo) MarkOrphans(ctx context.Context) error {
	e, _ := json.Marshal(derr("interrupted",
		"Сервер перезапустился во время деплоя.",
		"Запусти деплой заново — состояние сервера не изменилось."))
	const q = `
		UPDATE deployments
		SET status='failed', error=$1, updated_at=NOW()
		WHERE status IN ('queued','running')`
	_, err := r.db.ExecContext(ctx, q, e)
	return err
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
