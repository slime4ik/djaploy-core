package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/slime4ik/djaploy-core/internal/cfg"
	"github.com/slime4ik/djaploy-core/internal/github"
)

var ErrForbidden = errors.New("forbidden")
var errCDPaidOnly = errors.New("cd_paid_only")
var errCDDemo = errors.New("cd_demo_repo")

// InstallationResolver hands out tokens for git access. *auth.UserService implements it: for
// GitHub an installation token by installation_id, for GitLab a user OAuth token with auto refresh.
type InstallationResolver interface {
	GetInstallationIDByUserID(ctx context.Context, userID string) (int64, error)
	GitLabToken(ctx context.Context, userID string) (string, error)
}

// ReferralRewarder grants a referral reward on a successful deploy (implemented by *referral.Service).
type ReferralRewarder interface {
	RewardIfReferred(ctx context.Context, userID string)
}

// PlanLimiter is the project limit and feature access of a plan (implemented by *billing.Service).
type PlanLimiter interface {
	ProjectLimit(ctx context.Context, userID string) int     // personal limit, -1 means unlimited
	TeamProjectLimit(ctx context.Context, teamID string) int // team limit, -1 means unlimited
	CDAllowed(ctx context.Context, userID string) bool       // personal auto deploy on push (paid plans only)
	TeamCDAllowed(ctx context.Context, teamID string) bool   // team auto deploy on push
}

// CreateRequest is what the frontend sends.
type CreateRequest struct {
	RepoFullName string `json:"repo_full_name"`
	Provider     string `json:"provider"` // github (the default) | gitlab
	Domain       string `json:"domain"`
	ServerIP     string `json:"server_ip"`
	SSHUser      string `json:"ssh_user"`
	SSHPassword  string `json:"ssh_password"`
	Env          string `json:"env"`

	// what we need to know about the user's compose (all have defaults)
	TeamID       string `json:"team_id"`      // deploy into a team, so every member sees the project
	ProjectType  string `json:"project_type"` // web (domain plus Caddy) | worker (bot or worker, no ports)
	Framework    string `json:"framework"`    // django | other, Django specifics are added for django only
	AppService   string `json:"app_service"`
	AppPort      int    `json:"app_port"`
	ServeStatic  *bool  `json:"serve_static"` // nil means true
	ServeMedia   *bool  `json:"serve_media"`  // nil means true (Caddy serves /media; set false when media lives in S3)
	StaticVolume string `json:"static_volume"`
	MediaVolume  string `json:"media_volume"`

	// optional creation of a Django superuser
	CreateSuperuser bool   `json:"create_superuser"`
	SuUsername      string `json:"su_username"`
	SuEmail         string `json:"su_email"`
	SuPassword      string `json:"su_password"`

	EnableCD       bool   `json:"enable_cd"`        // auto deploy on git push
	NonRoot        bool   `json:"non_root"`         // create a separate deploy user and move off root
	EnableVPN      bool   `json:"enable_vpn"`       // bring up our VPN (AmneziaWG) on the server
	VPNPaths       string `json:"vpn_paths"`        // comma separated paths (/admin, /grafana) to close off to outsiders
	AllowedIPs     string `json:"allowed_ips"`      // trusted IPs and subnets for protected paths (a VPN of their own)
	EnableGrafana  bool   `json:"enable_grafana"`   // bring up Grafana at /grafana
	DeployUserName string `json:"deploy_user_name"` // name of the non-root user (deploy by default)
	SSHPubKey      string `json:"ssh_pubkey"`       // the user's public key, installed for the deploy user for direct ssh
}

// job is one queued task. The secrets (token, sshPassword, env, su_password) live here only and
// never reach the database.
type job struct {
	dep         *Deployment
	token       string
	sshUser     string
	sshPassword string
	env         string
	name        string

	createSU   bool
	suUsername string
	suEmail    string
	suPassword string

	nonRoot        bool
	enableVPN      bool
	userPubKey     string
	deployUserName string

	// redeploy: update the code over the key, no password
	redeploy bool
	keyPEM   string

	// rollback to a previous version (we deploy one specific commit)
	rollback    bool
	rollbackSHA string

	isCD bool // the redeploy was triggered by auto deploy (git push), which picks the notification category
}

// TeamAccess is team membership (implemented by *teams.Repo), used for shared project visibility.
type TeamAccess interface {
	TeamIDsOf(ctx context.Context, userID string) ([]string, error)
	IsMember(ctx context.Context, teamID, userID string) (bool, error)
	LogActivity(ctx context.Context, teamID, actorID, action, detail string)
}

// logTeam writes an event into the team feed when the project belongs to a team and teams is wired in.
func (s *Service) logTeam(ctx context.Context, dep *Deployment, actorID, action string) {
	if s.teams != nil && dep.TeamID != "" {
		s.teams.LogActivity(ctx, dep.TeamID, actorID, action, dep.Repo)
	}
}

// Notifier sends notifications (implemented by *telegram.Service). Optional.
type Notifier interface {
	Notify(ctx context.Context, userID, category, text string)
	NotifyTeam(ctx context.Context, teamID, category, text string)
	NotifyTeamExcept(ctx context.Context, teamID, exceptUserID, category, text string)
	NotifyChat(chatID int64, text string)
}

type Service struct {
	cfg      *cfg.Config
	resolver InstallationResolver
	repo     *Repo
	store    *Store
	jobs     chan *job
	encKey   []byte
	limiter  PlanLimiter      // optional: project limit by plan
	teams    TeamAccess       // optional: team membership, for shared project visibility
	notifier Notifier         // optional: deploy notifications
	referral ReferralRewarder // optional: referral reward on a successful deploy

	// serverLocks serializes WEB deploys onto one server: the shared Caddy gateway, the host ports
	// and the caddy reload are shared resources, and two parallel deploys to one IP must not tear
	// them apart.
	serverLocks sync.Map // server_ip -> *sync.Mutex
}

// lockServer takes the server lock for the duration of a deploy, protecting the shared gateway
// and ports. It returns the unlock function.
func (s *Service) lockServer(ip string) func() {
	m, _ := s.serverLocks.LoadOrStore(ip, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// SetLimiter wires in the plan limit checks (called from main once billing exists).
func (s *Service) SetLimiter(l PlanLimiter) { s.limiter = l }

// SetNotifier wires in notifications (called from main once telegram exists).
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// SetReferral wires in referral rewards (called from main once referral exists).
func (s *Service) SetReferral(r ReferralRewarder) { s.referral = r }

// tgEsc and tgSpoiler escape text and wrap it in a spoiler for Telegram notifications
// (parse_mode HTML). They live here so the deploy package does not have to import telegram, which
// stays decoupled behind the Notifier interface.
func tgEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
func tgSpoiler(s string) string { return "<tg-spoiler>" + tgEsc(s) + "</tg-spoiler>" }

// notifyDeploy reports the deploy result once the worker has finished the job.
func (s *Service) notifyDeploy(j *job) {
	if s.notifier == nil {
		return
	}
	dep := j.dep
	dep.mu.Lock()
	status, depErr, domain, repo, teamID, userID := dep.Status, dep.Err, dep.Domain, dep.Repo, dep.TeamID, dep.UserID
	dep.mu.Unlock()

	site := domain
	if site == "" {
		site = repo
	}
	cat := "deploys"
	if j.isCD {
		cat = "cd"
	}
	// the domain goes under a spoiler for privacy in Telegram, the rest is escaped for parse_mode HTML
	ss := tgSpoiler(site)
	var text string
	switch status {
	case StatusSuccess:
		if j.isCD {
			text = "✅ " + ss + " обновлён (git push)"
		} else {
			text = "✅ " + ss + " развёрнут"
		}
	case StatusFailed:
		text = "❌ деплой " + ss + " упал"
		if depErr != nil {
			text += ": " + tgEsc(depErr.Message)
		}
	default:
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if teamID != "" {
		s.notifier.NotifyTeam(ctx, teamID, cat, text)
	} else {
		s.notifier.Notify(ctx, userID, cat, text)
	}
}

// SetTeamAccess wires in team membership (called from main once teams exists).
func (s *Service) SetTeamAccess(t TeamAccess) { s.teams = t }

// canAccess: a personal project is available to its creator, a team project only to the current
// members of that team. The creator of a team project loses access after leaving or being removed
// from the team; if the team itself is deleted, team_id becomes NULL through the foreign key and
// the project turns personal again.
func (s *Service) canAccess(ctx context.Context, dep *Deployment, userID string) bool {
	if dep.TeamID != "" {
		if s.teams == nil {
			return false
		}
		ok, _ := s.teams.IsMember(ctx, dep.TeamID, userID)
		return ok
	}
	return dep.UserID == userID
}

func NewService(cfg *cfg.Config, resolver InstallationResolver, repo *Repo, workers int) *Service {
	if workers < 1 {
		workers = 1
	}
	// on startup, mark deploys left hanging as failed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = repo.MarkOrphans(ctx)
	cancel()

	s := &Service{
		cfg: cfg, resolver: resolver, repo: repo,
		store: NewStore(), jobs: make(chan *job, 64),
		encKey: deriveKey(cfg.JWTSecret),
	}
	// the GitLab base used for cloning (gitlab.com or a self-hosted one from env)
	if cfg.GitLabBaseURL != "" {
		gitlabBaseURL = cfg.GitLabBaseURL
	}
	for i := 0; i < workers; i++ {
		go s.worker()
	}
	return s
}

// Start validates the request, mints an installation token, creates the deploy, writes it to the
// database and puts it in the queue.
func (s *Service) Start(ctx context.Context, userID string, req CreateRequest) (*Deployment, *DeployError) {
	if s.repo.MaintenanceOn(ctx) {
		return nil, errMaintenance()
	}
	dep, de := buildDeployment(userID, req)
	if de != nil {
		return nil, de
	}

	// Guard rail: one repository means one project per server. The directory, the containers and
	// the gateway snippet are all named after the repo, so a second deploy of the same repo onto the
	// same server would overwrite the first one and take a working site down. Applies to web
	// projects and workers alike.
	if existing, taken := s.repo.RepoOnServer(ctx, dep.Repo, dep.ServerIP, userID, ""); taken {
		return nil, derr("repo_on_server",
			"Репозиторий "+dep.Repo+" уже развёрнут на этом сервере (проект «"+existing+"»).",
			"Один репозиторий — один проект на сервере (иначе контейнеры и папки совпадут и сломают друг друга). Разверни на ДРУГОЙ сервер, либо обнови тот проект кнопкой «Передеплоить».")
	}

	// Guard against a duplicate domain: a second site cannot take a domain that is already in use,
	// which would clash in the shared Caddy gateway and confuse the certificates.
	if !dep.IsWorker() {
		if existing, taken := s.repo.DomainInUse(ctx, dep.Domain, userID, ""); taken {
			return nil, derr("domain_taken",
				"Домен "+dep.Domain+" уже занят твоим проектом «"+existing+"».",
				"Укажи другой домен. Если хочешь обновить тот проект — открой его и нажми «Передеплоить».")
		}
	}

	// deploying into a team requires the user to actually be a member
	if dep.TeamID != "" {
		if s.teams == nil {
			return nil, derr("forbidden", "Команды недоступны.", "")
		}
		if ok, err := s.teams.IsMember(ctx, dep.TeamID, userID); err != nil || !ok {
			return nil, derr("forbidden", "Ты не участник этой команды.", "")
		}
	}

	// Project limit: a team project counts against the TEAM limit, a personal one against the
	// user's own plan.
	if s.limiter != nil {
		if dep.TeamID != "" {
			if limit := s.limiter.TeamProjectLimit(ctx, dep.TeamID); limit >= 0 {
				if n, err := s.repo.CountActiveByTeam(ctx, dep.TeamID); err == nil && n >= limit {
					return nil, derr("limit_reached",
						"Достигнут лимит проектов команды ("+itoa(limit)+").",
						"Удали ненужный проект команды или оформи тариф «Команда» на странице команды.")
				}
			}
		} else if limit := s.limiter.ProjectLimit(ctx, userID); limit >= 0 {
			if n, err := s.repo.CountActiveByUser(ctx, userID); err == nil && n >= limit {
				return nil, derr("limit_reached",
					"Достигнут лимит проектов на твоём тарифе ("+itoa(limit)+").",
					"Удали ненужный проект (меню ⋯ → Отвязать) или оформи тариф повыше на дашборде.")
			}
		}
		// Auto deploy (CD) is a paid feature, and on the free plan we switch it off quietly.
		// A team project is judged by the team plan, a personal one by the user's plan.
		if dep.CDEnabled {
			cdOK := s.limiter.CDAllowed(ctx, userID)
			if dep.TeamID != "" {
				cdOK = s.limiter.TeamCDAllowed(ctx, dep.TeamID)
			}
			if !cdOK {
				dep.CDEnabled = false
			}
		}
	}

	// The demo repository is public: it clones with no token and needs no GitHub App.
	// CD is forced off because the user cannot push to someone else's demo repo.
	if isDemoRepo(req.RepoFullName) {
		dep.CDEnabled = false
	}
	token, de := s.gitToken(ctx, dep)
	if de != nil {
		return nil, de
	}

	// Deploying the same repo and server again after a failure: we drop the earlier failed attempts
	// so broken rows do not pile up in the list. Successful and running ones are left alone.
	if failedIDs, ferr := s.repo.DeleteFailedTarget(ctx, userID, dep.Repo, dep.Provider, dep.ServerIP); ferr == nil {
		for _, fid := range failedIDs {
			s.store.Remove(fid)
		}
	}

	s.store.Add(dep)
	if err := s.repo.Create(ctx, dep); err != nil {
		log.Printf("deploy: repo.Create failed: %v", err) // the real cause stays in the server logs
		return nil, derr("internal", "Не удалось сохранить деплой на нашей стороне.",
			"Это проблема сервиса, не твоих данных — мы уже видим её в логах. Попробуй чуть позже.")
	}
	dep.log("", KindStep, "В очереди на деплой…")

	s.jobs <- &job{
		dep:            dep,
		token:          token,
		sshUser:        dep.SSHUser,
		sshPassword:    req.SSHPassword,
		env:            req.Env,
		name:           sanitizeName(req.RepoFullName),
		createSU:       dep.HasSuperuser, // already accounts for the framework (django only)
		suUsername:     strings.TrimSpace(req.SuUsername),
		suEmail:        strings.TrimSpace(req.SuEmail),
		suPassword:     req.SuPassword,
		nonRoot:        req.NonRoot,
		enableVPN:      req.EnableVPN,
		userPubKey:     strings.TrimSpace(req.SSHPubKey),
		deployUserName: sanitizeUser(req.DeployUserName),
	}
	s.logTeam(ctx, dep, userID, "deploy")
	return dep, nil
}

// sanitizeUser turns a name into a valid linux login (a-z0-9_-, starting with a letter).
// Anything empty or unusable becomes "deploy".
func sanitizeUser(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || !(out[0] >= 'a' && out[0] <= 'z') || len(out) > 32 {
		return "deploy"
	}
	return out
}

func (s *Service) worker() {
	for j := range s.jobs {
		// Web deploys onto one server are serialized: the shared Caddy gateway and the host ports are
		// shared resources. Workers and bots take no lock (they have no gateway) and still deploy in
		// parallel.
		var unlock func()
		if j.dep != nil && !j.dep.IsWorker() {
			unlock = s.lockServer(j.dep.ServerIP)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
		switch {
		case j.rollback:
			runRollback(ctx, s.repo, j.dep, j.keyPEM, j.token, j.rollbackSHA)
		case j.redeploy:
			runRedeploy(ctx, s.repo, j.dep, j.keyPEM, j.token)
		default:
			runDeployment(ctx, s.repo, s.encKey, j)
		}
		cancel()
		if unlock != nil {
			unlock()
		}
		s.notifyDeploy(j) // report the result on Telegram

		// Referral reward: the referred user actually deployed, so both sides get Max (the referral
		// package makes it once-only). Successful deploys only; a redeploy or rollback is fine too,
		// since the referred user's first success still happens once.
		if s.referral != nil && j.dep != nil && j.dep.Status == StatusSuccess {
			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			s.referral.RewardIfReferred(rctx, j.dep.UserID)
			rcancel()
		}
	}
}

// DemoRepo is our public example. It deploys with no GitHub App connected (an anonymous clone),
// so a user can try the service before trusting it with their own repositories.
const DemoRepo = "slime4ik/djaploy-demo"

func isDemoRepo(fullName string) bool {
	return strings.EqualFold(strings.TrimSpace(fullName), DemoRepo)
}

// gitToken returns the token for the deploy's git operations, per provider. The demo repo is
// public and needs none; GitLab and GitHub use the credentials of the project creator. On a team
// project the actor can be any member, but repository and server access always stays bound to the
// creator of the project.
func (s *Service) gitToken(ctx context.Context, dep *Deployment) (string, *DeployError) {
	if isDemoRepo(dep.Repo) {
		return "", nil
	}
	owner := dep.UserID
	if dep.IsGitLab() {
		t, err := s.resolver.GitLabToken(ctx, owner)
		if err != nil {
			log.Printf("deploy: gitlab token for user %s: %v", owner, err)
			return "", derr("gitlab_token_failed",
				"Не удалось получить доступ к GitLab.",
				"Проверь в настройках, что GitLab привязан к аккаунту, и попробуй снова.")
		}
		return t, nil
	}
	return s.mintToken(ctx, owner)
}

// mintToken issues the installation token for this user's git access.
func (s *Service) mintToken(ctx context.Context, userID string) (string, *DeployError) {
	instID, err := s.resolver.GetInstallationIDByUserID(ctx, userID)
	if err != nil {
		return "", derr("not_connected", "GitHub не подключён или нет доступа к репозиториям.",
			"На дашборде подключи GitHub и дай приложению доступ к этому репозиторию.")
	}
	token, err := github.InstallationToken(s.cfg.GitHunAppID, s.cfg.GitHubAppPemPath, instID)
	if err != nil {
		return "", derr("token_failed", "Не удалось получить токен доступа к GitHub.",
			"Переподключи приложение к репозиториям и попробуй снова.")
	}
	return token, nil
}

// Redeploy updates an already deployed project over the stored key, with no password and no form.
func (s *Service) Redeploy(ctx context.Context, id, userID string) (*Deployment, *DeployError) {
	if s.repo.MaintenanceOn(ctx) {
		return nil, errMaintenance()
	}
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return nil, derr("not_found", "Деплой не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return nil, derr("forbidden", "Нет доступа к этому деплою.", "")
	}
	if keyEnc == "" {
		return nil, derr("no_key", "Для этого проекта нет сохранённого доступа.",
			"Запусти обычный деплой — он установит ключ, дальше обновления пойдут в один клик.")
	}
	key, derr2 := s.decryptKey(keyEnc)
	if derr2 != nil {
		return nil, derr2
	}
	// Always the project owner's token: a team member may have no access to the repository (no
	// GitHub App installed) while the owner certainly does.
	token, de := s.gitToken(ctx, dep)
	if de != nil {
		return nil, de
	}

	if s.isBusy(id) {
		return nil, derr("busy", "Этот проект уже разворачивается.",
			"Дождись окончания текущего деплоя и обнови ещё раз.")
	}

	live := rerunClone(dep, redeploySteps(frameworkOrDefault(dep.ServerState.Framework) == frameworkDjango))
	s.store.Add(live)
	_ = s.repo.SaveState(ctx, live)
	_ = s.repo.SetHealth(ctx, live.ID, "") // clear "down" during the rebuild, the monitor rechecks it
	live.log("", KindStep, "Обновление в очереди…")
	s.jobs <- &job{dep: live, token: token, redeploy: true, keyPEM: key}
	s.logTeam(ctx, live, userID, "redeploy")
	return live, nil
}

// Rollback takes the project back to the previous successfully deployed version, from the
// release history.
func (s *Service) Rollback(ctx context.Context, id, userID string) (*Deployment, *DeployError) {
	if s.repo.MaintenanceOn(ctx) {
		return nil, errMaintenance()
	}
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return nil, derr("not_found", "Деплой не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return nil, derr("forbidden", "Нет доступа к этому деплою.", "")
	}
	if keyEnc == "" {
		return nil, derr("no_key", "Для этого проекта нет сохранённого доступа.",
			"Запусти обычный деплой — он установит ключ.")
	}
	rel := dep.ServerState.Releases
	n := len(rel)
	var target string
	switch {
	case dep.Status == StatusFailed && n >= 1:
		// the last deploy failed, so we restore the last working version (the top of the stack)
		target = rel[n-1].SHA
	case n >= 2:
		// the deploy works, so we step one version back
		target = rel[n-2].SHA
	default:
		return nil, derr("no_previous", "Нет предыдущей версии для отката.",
			"Откат доступен, когда проект успешно разворачивался хотя бы раз.")
	}

	key, derr2 := s.decryptKey(keyEnc)
	if derr2 != nil {
		return nil, derr2
	}
	token, de := s.gitToken(ctx, dep)
	if de != nil {
		return nil, de
	}
	if s.isBusy(id) {
		return nil, derr("busy", "Этот проект уже разворачивается.",
			"Дождись окончания текущего деплоя и попробуй снова.")
	}

	live := rerunClone(dep, rollbackSteps(dep.IsWorker()))
	s.store.Add(live)
	_ = s.repo.SaveState(ctx, live)
	_ = s.repo.SetHealth(ctx, live.ID, "") // clear "down" during the rebuild, the monitor rechecks it
	live.log("", KindStep, "Откат на предыдущую версию в очереди…")
	s.jobs <- &job{dep: live, token: token, rollback: true, rollbackSHA: target, keyPEM: key}
	s.logTeam(ctx, live, userID, "rollback")
	return live, nil
}

// RedeployForCD is the automatic update driven by a push webhook. It finds the newest deploy of
// that repo with CD enabled and updates it. It returns (started, reason) for the webhook log.
func (s *Service) RedeployForCD(ctx context.Context, repo, provider string) (bool, string) {
	dep, keyEnc, err := s.repo.LatestCDByRepo(ctx, repo, provider)
	if err != nil || keyEnc == "" {
		return false, "нет деплоя с включённым CD"
	}
	return s.redeployFromHook(ctx, dep, keyEnc)
}

// RedeployForGitLabCD is the same for GitLab. GitLab has no HMAC signature, so we compare the
// plain secret from X-Gitlab-Token with the project's deterministic secret.
func (s *Service) RedeployForGitLabCD(ctx context.Context, repo, gotToken string) (bool, string) {
	dep, keyEnc, err := s.repo.LatestCDByRepo(ctx, repo, ProviderGitLab)
	if err != nil || keyEnc == "" {
		return false, "нет деплоя с включённым CD"
	}
	if gotToken == "" || !hmac.Equal([]byte(gotToken), []byte(s.GitLabHookSecret(dep.ID))) {
		return false, "bad token"
	}
	return s.redeployFromHook(ctx, dep, keyEnc)
}

// GitLabHookSecret is the project's webhook secret: a deterministic HMAC of the deploy id. It is
// never stored in the database, and the user copies it into the GitLab webhook settings.
func (s *Service) GitLabHookSecret(depID string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.JWTSecret))
	mac.Write([]byte("gitlab-hook:" + depID))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// redeployFromHook is the shared tail of the CD webhooks: plan, busy check, key, token, queue.
func (s *Service) redeployFromHook(ctx context.Context, dep *Deployment, keyEnc string) (bool, string) {
	if s.repo.MaintenanceOn(ctx) {
		return false, "идут технические работы — автодеплой на паузе"
	}
	// CD is a paid feature, so we check the CURRENT plan: a subscription may have expired while the
	// cd_enabled flag stayed TRUE. Without this check CD would keep running after the subscription
	// ended.
	if s.limiter != nil {
		allowed := s.limiter.CDAllowed(ctx, dep.UserID)
		if dep.TeamID != "" {
			allowed = s.limiter.TeamCDAllowed(ctx, dep.TeamID)
		}
		if !allowed {
			return false, "CD недоступен — подписка не активна (тариф без авто-деплоя)"
		}
	}
	if s.isBusy(dep.ID) {
		return false, "деплой уже идёт — пропускаю"
	}
	key, derr2 := s.decryptKey(keyEnc)
	if derr2 != nil {
		return false, "ошибка ключа доступа"
	}
	token, de := s.gitToken(ctx, dep)
	if de != nil {
		return false, "ошибка токена git-провайдера"
	}
	live := rerunClone(dep, redeploySteps(frameworkOrDefault(dep.ServerState.Framework) == frameworkDjango))
	s.store.Add(live)
	_ = s.repo.SaveState(ctx, live)
	_ = s.repo.SetHealth(ctx, live.ID, "") // clear "down" during the rebuild, the monitor rechecks it
	live.log("", KindStep, "Авто-деплой по git push…")
	s.jobs <- &job{dep: live, token: token, redeploy: true, keyPEM: key, isCD: true}
	s.logTeam(ctx, live, "", "cd") // an empty actor means the system did it (git push)
	return true, "запущен"
}

// isBusy reports whether a deploy for this id is already running, which keeps two workers out of
// the same folder.
func (s *Service) isBusy(id string) bool {
	if live := s.store.Get(id); live != nil {
		live.mu.Lock()
		defer live.mu.Unlock()
		return live.Status == StatusQueued || live.Status == StatusRunning
	}
	return false
}

// SetCD turns auto deploy on push on or off. Access is granted to the owner or a team member.
// Turning it on requires a paid plan (a team project is judged by the team plan).
func (s *Service) SetCD(ctx context.Context, id, userID string, enabled bool) error {
	dep, _, err := s.repo.getFull(ctx, id)
	if err != nil {
		return sql.ErrNoRows
	}
	if !s.canAccess(ctx, dep, userID) {
		return ErrForbidden
	}
	if enabled && s.limiter != nil {
		allowed := s.limiter.CDAllowed(ctx, dep.UserID)
		if dep.TeamID != "" {
			allowed = s.limiter.TeamCDAllowed(ctx, dep.TeamID)
		}
		if !allowed {
			return errCDPaidOnly
		}
	}
	// the demo repo cannot be pushed to by the user, so CD would be pointless and stays off
	if enabled && isDemoRepo(dep.Repo) {
		return errCDDemo
	}
	if err := s.repo.SetCDByID(ctx, id, enabled); err != nil {
		return err
	}
	if live := s.store.Get(id); live != nil {
		live.mu.Lock()
		live.CDEnabled = enabled
		live.mu.Unlock()
	}
	action := "cd_enabled"
	text := "▶️ Включён авто-деплой по push: " + tgSpoiler(projectLabel(dep))
	if !enabled {
		action = "cd_disabled"
		text = "⏸ Выключен авто-деплой по push: " + tgSpoiler(projectLabel(dep))
	}
	s.logTeam(ctx, dep, userID, action)
	s.notifyTeamChange(ctx, dep, userID, text)
	return nil
}

// projectLabel is how a project is named in notifications: the custom name, else domain or repo.
func projectLabel(d *Deployment) string {
	if d.Name != "" {
		return d.Name
	}
	if d.Domain != "" {
		return d.Domain
	}
	return d.Repo
}

// notifyTeamChange tells the team about a project change, skipping the person who made it.
// Personal projects send nothing: the user did it themselves, so there is nothing to report.
func (s *Service) notifyTeamChange(ctx context.Context, dep *Deployment, actorID, text string) {
	if s.notifier != nil && dep.TeamID != "" {
		s.notifier.NotifyTeamExcept(ctx, dep.TeamID, actorID, "team", text)
	}
}

func (s *Service) decryptKey(enc string) (string, *DeployError) {
	key, err := decrypt(s.encKey, enc)
	if err != nil {
		return "", derr("key_error", "Не удалось расшифровать ключ доступа.",
			"Запусти обычный деплой заново, чтобы переустановить доступ.")
	}
	return key, nil
}

// rerunClone is a fresh live copy of a deploy for another run: same parameters and same ID, but a
// clean runtime state (logs, subscribers, steps).
func rerunClone(src *Deployment, steps []StepState) *Deployment {
	return &Deployment{
		ID: src.ID, UserID: src.UserID, TeamID: src.TeamID, Repo: src.Repo, Provider: src.Provider, Name: src.Name, Domain: src.Domain, ServerIP: src.ServerIP,
		AppService: src.AppService, AppPort: src.AppPort, ServeStatic: src.ServeStatic, ServeMedia: src.ServeMedia,
		StaticVolume: src.StaticVolume, MediaVolume: src.MediaVolume, HasSuperuser: src.HasSuperuser,
		SSHUser: src.SSHUser, CDEnabled: src.CDEnabled,
		ServerState: src.ServerState, // CRITICAL: without it a redeploy or CD wipes vpn, deploy_user and paths
		Status:      StatusQueued, Steps: steps, CreatedAt: src.CreatedAt,
		subs: map[chan LogLine]struct{}{}, sshKeyEnc: src.sshKeyEnc,
	}
}

// Find returns the live deploy from memory, or the stored one from the database. Access is
// granted to the owner OR a member of the project's team.
func (s *Service) Find(ctx context.Context, id, userID string) (*Deployment, error) {
	if dep := s.store.Get(id); dep != nil {
		if !s.canAccess(ctx, dep, userID) {
			return nil, ErrForbidden
		}
		return dep, nil
	}
	dep, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !s.canAccess(ctx, dep, userID) {
		return nil, ErrForbidden
	}
	return dep, nil
}

func (s *Service) List(ctx context.Context, userID string) ([]DeploymentSummary, error) {
	var teamIDs []string
	if s.teams != nil {
		teamIDs, _ = s.teams.TeamIDsOf(ctx, userID)
	}
	return s.repo.ListVisible(ctx, userID, teamIDs, 50)
}

// AppLogs returns the latest container logs of the project from the user's server (docker compose logs).
func (s *Service) AppLogs(ctx context.Context, id, userID string) (string, *DeployError) {
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return "", derr("not_found", "Деплой не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return "", derr("forbidden", "Нет доступа.", "")
	}
	if keyEnc == "" {
		return "", derr("no_key", "Нет доступа к серверу этого деплоя.",
			"Запусти обычный деплой — он установит ключ доступа.")
	}
	key, de := s.decryptKey(keyEnc)
	if de != nil {
		return "", de
	}
	sshc, hkErr, err := dialKeyPinned(ctx, s.repo, dep.UserID, dep.ServerIP, dep.SSHUser, key)
	if hkErr != nil {
		return "", hkErr
	}
	if err != nil {
		return "", derr("ssh_failed", "Не удалось подключиться к серверу.",
			"Возможно, сервер недоступен или ключ удалили — запусти обычный деплой заново.")
	}
	defer sshc.Close()

	dir := "/opt/djaploy/" + sanitizeName(dep.Repo)
	cmd := "cd " + sq(dir) + " && docker compose -f docker-compose.yml -f docker-compose.caddy.yml logs --no-color --tail 300 2>&1"
	var b strings.Builder
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := sshc.Run(cctx, cmd, func(line string) {
		b.WriteString(line)
		b.WriteByte('\n')
	}); err != nil {
		// partial output is still worth returning
		if b.Len() == 0 {
			return "", derr("logs_failed", "Не удалось получить логи.", "Проверь, что проект запущен.")
		}
	}
	return b.String(), nil
}

// VPNConfig reads the client WireGuard config off the user's server. It is NOT in our database:
// the secret lives on the user's server only. The user downloads the .conf and imports it into
// WireGuard.
func (s *Service) VPNConfig(ctx context.Context, id, userID string) (string, *DeployError) {
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return "", derr("not_found", "Деплой не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return "", derr("forbidden", "Нет доступа.", "")
	}
	if !dep.ServerState.VPN {
		return "", derr("no_vpn", "VPN для этого деплоя не поднимался.",
			"Включи «VPN-доступ» при деплое — тогда сгенерим конфиг.")
	}
	if keyEnc == "" {
		return "", derr("no_key", "Нет доступа к серверу этого деплоя.", "Запусти деплой заново.")
	}
	key, de := s.decryptKey(keyEnc)
	if de != nil {
		return "", de
	}
	sshc, hkErr, err := dialKeyPinned(ctx, s.repo, dep.UserID, dep.ServerIP, dep.SSHUser, key)
	if hkErr != nil {
		return "", hkErr
	}
	if err != nil {
		return "", derr("ssh_failed", "Не удалось подключиться к серверу.", "Возможно, сервер недоступен.")
	}
	defer sshc.Close()

	path := "/opt/djaploy/" + sanitizeName(dep.Repo) + "/.djaploy/wg-client.conf"
	var b strings.Builder
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := sshc.Run(cctx, "cat "+sq(path), func(line string) {
		b.WriteString(line)
		b.WriteByte('\n')
	}); err != nil || b.Len() == 0 {
		return "", derr("vpn_config_failed", "Не удалось прочитать VPN-конфиг с сервера.",
			"Попробуй переразвернуть с включённым VPN.")
	}
	// downloading the VPN config is a security event, so the team sees it in the feed
	s.logTeam(ctx, dep, userID, "vpn_config_downloaded")
	return strings.TrimSpace(b.String()), nil
}

// Delete removes a project. Modes: unlink (from the dashboard only), teardown (plus docker
// compose down, with data and volumes kept), purge (plus down -v and rm -rf of the folder, a FULL
// cleanup of the server).
func (s *Service) Delete(ctx context.Context, id, userID string, teardown, purge bool) *DeployError {
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return derr("not_found", "Проект не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return derr("forbidden", "Нет доступа к этому проекту.", "")
	}
	// The server side of the deletion is NOT tied to the request ctx. The frontend removes the
	// project optimistically and may time out while the SSH cleanup runs (purge does down -v --rmi
	// local and tears the VPN down, which takes seconds). Otherwise a cancelled ctx would abort
	// repo.Delete, the row would survive and the user would have to delete twice.
	opCtx, opCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer opCancel()
	if (teardown || purge) && keyEnc != "" {
		if key, de := s.decryptKey(keyEnc); de == nil {
			// The host key is verified here too, but a deletion is never blocked by it: if the
			// server was rebuilt there is nothing of ours left to clean up, and the user still has
			// to be able to drop the row (otherwise the project becomes undeletable).
			sshc, hkErr, e := dialKeyPinned(opCtx, s.repo, dep.UserID, dep.ServerIP, dep.SSHUser, key)
			if hkErr != nil {
				log.Printf("deploy: delete %s: skipping cleanup on the server, %s", id, hkErr.Message)
			}
			if e == nil {
				dir := "/opt/djaploy/" + sanitizeName(dep.Repo)
				base := "cd " + sq(dir) + " && docker compose -f docker-compose.yml -f docker-compose.caddy.yml "
				var cmd string
				if purge {
					// down -v --rmi local removes the containers, the volumes (the data) and the images
					// built for this project, then we delete the project folder. Nothing of ours is left.
					cmd = base + "down -v --rmi local --remove-orphans 2>&1 || true; rm -rf " + sq(dir)
					// Tear the VPN down if we brought it up, otherwise awg0 keeps holding the port, the
					// "as if we were never here" promise breaks and the next deploy fails. sudo -n works
					// under root or NOPASSWD and is skipped quietly otherwise, best effort.
					if dep.ServerState.VPN {
						cmd += `; SUDO=""; [ "$(id -u)" = "0" ] || SUDO="sudo -n"` +
							`; $SUDO systemctl disable --now awg-quick@awg0 2>/dev/null || true` +
							`; $SUDO awg-quick down awg0 2>/dev/null || true` +
							`; $SUDO ip link delete awg0 2>/dev/null || true` +
							`; $SUDO rm -rf /etc/amnezia/amneziawg /etc/sysctl.d/99-djaploy-wg.conf 2>/dev/null || true` +
							// the port may have been picked automatically (51820..51830), so clean the range
							`; for pp in $(seq 51820 51830); do $SUDO iptables -D INPUT -p udp --dport $pp -j ACCEPT 2>/dev/null; $SUDO ufw delete allow $pp/udp 2>/dev/null; done || true`
					}
					// remove our access key from authorized_keys, as if we were never here
					if line, perr := pubLineFromPriv(key); perr == nil {
						ak := "$HOME/.ssh/authorized_keys"
						cmd += "; grep -vF " + sq(line) + " " + ak + " > " + ak + ".djtmp 2>/dev/null && mv " + ak + ".djtmp " + ak + " || true"
					}
				} else {
					// down without -v stops the containers and keeps the volumes and the database
					cmd = base + "down --remove-orphans 2>&1 || true"
				}
				// Take the site out of the shared Caddy gateway while the OTHER sites keep working. If
				// this was the LAST site we shut the gateway down entirely, because a reload on an empty
				// config fails and the deleted site would hang around until a restart. Workers have no
				// snippet.
				if !dep.IsWorker() {
					name := sanitizeName(dep.Repo)
					gw := "/opt/djaploy/_gateway"
					cmd += "; rm -f " + sq(gw+"/sites/"+name+".caddy") +
						"; if [ -n \"$(ls -A " + sq(gw+"/sites") + " 2>/dev/null)\" ]; then" +
						" (cd " + sq(gw) + " && docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile) 2>/dev/null || true;" +
						" else (cd " + sq(gw) + " && docker compose down) 2>/dev/null || true; fi"
				}
				cctx, cancel := context.WithTimeout(opCtx, 90*time.Second)
				_ = sshc.Run(cctx, cmd, func(string) {})
				cancel()
				sshc.Close()
			}
		}
		// best effort: even if the server side failed, the row is unlinked from the database
	}
	if err := s.repo.Delete(opCtx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return derr("not_found", "Проект не найден.", "")
		}
		log.Printf("deploy: delete %s: %v", id, err)
		return derr("internal", "Не удалось удалить проект.", "Попробуй ещё раз.")
	}
	s.store.Remove(id)

	action, text := "unlinked", "📤 Проект «"+tgSpoiler(projectLabel(dep))+"» отвязан от djaploy (сервер не тронут)"
	switch {
	case purge:
		action, text = "purged", "🗑 Проект «"+tgSpoiler(projectLabel(dep))+"» полностью удалён с сервера (включая данные)"
	case teardown:
		action, text = "stopped", "⏹ Проект «"+tgSpoiler(projectLabel(dep))+"» остановлен на сервере (данные целы)"
	}
	// The user's last project on this server is gone, so the fingerprint goes with it. Otherwise a
	// rebuilt server would hit a mismatch with no server card left in the dashboard to reset from.
	if !s.repo.HasDeploymentsOn(opCtx, dep.UserID, dep.ServerIP) {
		_ = s.repo.ForgetHostPin(opCtx, dep.UserID, dep.ServerIP)
	}

	s.logTeam(opCtx, dep, userID, action)
	s.notifyTeamChange(opCtx, dep, userID, text)
	return nil
}

// ResetHostKey is the "server was rebuilt" action: forget the pinned host key so the next
// connection records a new one. Only for the user's own servers.
func (s *Service) ResetHostKey(ctx context.Context, userID, ip string) *DeployError {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return derr("bad_input", "Не указан сервер.", "")
	}
	if !s.repo.HasDeploymentsOn(ctx, userID, ip) {
		return derr("not_found", "У тебя нет проектов на этом сервере.", "")
	}
	if err := s.repo.ForgetHostPin(ctx, userID, ip); err != nil {
		log.Printf("deploy: reset host key %s: %v", ip, err)
		return derr("internal", "Не удалось сбросить отпечаток сервера.", "Попробуй ещё раз.")
	}
	hostKeyAlerted.Delete(ip) // background alerts for this server are allowed again
	if s.notifier != nil {
		s.notifier.Notify(ctx, userID, "deploys",
			"🔑 Отпечаток сервера "+tgSpoiler(ip)+" сброшен. При следующем подключении запомним новый ключ.")
	}
	return nil
}

// buildDeployment validates the request and fills in defaults, returning a Deployment with no secrets.
func buildDeployment(userID string, r CreateRequest) (*Deployment, *DeployError) {
	if strings.TrimSpace(r.RepoFullName) == "" || !strings.Contains(r.RepoFullName, "/") {
		return nil, derr("bad_input", "Не выбран репозиторий.", "Вернись на дашборд и выбери репозиторий из списка.")
	}
	worker := r.ProjectType == "worker"
	// only a web project needs a domain (a worker or bot has no inbound ports and no Caddy)
	domain := strings.TrimSpace(r.Domain)
	if !worker && !looksLikeDomain(domain) {
		return nil, derr("bad_input", "Домен выглядит некорректно: "+r.Domain,
			"Укажи домен вида app.example.com — без http:// и без слешей.")
	}
	ip := strings.TrimSpace(r.ServerIP)
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, derr("bad_input", "IP сервера некорректен: "+r.ServerIP,
			"Укажи IP-адрес твоего сервера, например 203.0.113.10.")
	}
	// SSRF protection: a deploy must not target internal or service addresses (loopback, private
	// networks, link-local and the cloud metadata range 169.254.0.0/16). A user's server is always
	// publicly reachable.
	if !isPublicIP(parsedIP) {
		return nil, derr("bad_input", "Этот IP не похож на публичный адрес сервера: "+r.ServerIP,
			"Укажи внешний (публичный) IP твоего VPS — приватные и служебные адреса недопустимы.")
	}
	if strings.TrimSpace(r.SSHPassword) == "" {
		return nil, derr("bad_input", "Не указан пароль для SSH.",
			"Введи пароль от root-доступа к серверу (тот, которым заходишь по ssh root@IP).")
	}
	framework := frameworkOrDefault(strings.TrimSpace(r.Framework))
	// a Django superuser only makes sense for Django, so any other stack ignores it
	createSU := r.CreateSuperuser && framework == frameworkDjango
	// the .env may be empty, since the user may have everything hardcoded in the project
	if createSU {
		if strings.TrimSpace(r.SuUsername) == "" || strings.TrimSpace(r.SuPassword) == "" {
			return nil, derr("bad_input", "Для суперпользователя нужны логин и пароль.",
				"Заполни логин и пароль администратора, либо выключи создание суперпользователя.")
		}
	}

	service := strings.TrimSpace(r.AppService)
	if service == "" {
		service = "web"
	}
	port := r.AppPort
	if port <= 0 || port > 65535 {
		port = 8000
	}
	serveStatic := r.ServeStatic == nil || *r.ServeStatic
	serveMedia := r.ServeMedia == nil || *r.ServeMedia
	staticVol := strings.TrimSpace(r.StaticVolume)
	if staticVol == "" {
		staticVol = "static_volume"
	}
	mediaVol := strings.TrimSpace(r.MediaVolume)
	if mediaVol == "" {
		mediaVol = "media_volume"
	}
	sshUser := strings.TrimSpace(r.SSHUser)
	if sshUser == "" {
		sshUser = "root"
	}

	return &Deployment{
		ID:           uuid.NewString(),
		UserID:       userID,
		TeamID:       strings.TrimSpace(r.TeamID),
		Repo:         r.RepoFullName,
		Provider:     providerOrDefault(strings.TrimSpace(r.Provider)),
		Domain:       domain,
		ServerIP:     ip,
		AppService:   service,
		AppPort:      port,
		ServeStatic:  serveStatic,
		ServeMedia:   serveMedia,
		StaticVolume: staticVol,
		MediaVolume:  mediaVol,
		HasSuperuser: createSU,
		SSHUser:      sshUser,
		CDEnabled:    r.EnableCD,
		ServerState: ServerState{
			ProjectType: projectType(worker),
			Framework:   framework,
			VPNPaths:    protectedPaths(r),
			AllowedIPs:  parseIPs(r.AllowedIPs),
			Grafana:     r.EnableGrafana && !worker, // Grafana hangs off Caddy, so it is web only
		},
		Status:    StatusQueued,
		Steps:     defaultSteps(createSU, r.EnableVPN, r.NonRoot, worker, framework == frameworkDjango),
		CreatedAt: time.Now(),
		subs:      map[chan LogLine]struct{}{},
	}, nil
}

// projectType normalizes the project type (web by default).
func projectType(worker bool) string {
	if worker {
		return "worker"
	}
	return "web"
}

// protectedPaths: paths only make sense when there is something to guard them with, either our
// VPN or the user's own IPs.
func protectedPaths(r CreateRequest) []string {
	if !r.EnableVPN && strings.TrimSpace(r.AllowedIPs) == "" {
		return nil
	}
	return parsePathsStr(r.VPNPaths)
}

// parseIPs validates a comma separated list of IPs and CIDRs and returns a normalized list,
// dropping anything unusable.
func parseIPs(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' }) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err == nil {
			out = append(out, p)
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			// a bare IP becomes /32 or /128
			if ip.To4() != nil {
				out = append(out, p+"/32")
			} else {
				out = append(out, p+"/128")
			}
		}
	}
	return out
}

// parsePathsStr turns "/admin, /grafana" into ["/admin","/grafana"], always with a leading slash.
func parsePathsStr(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' }) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out = append(out, p)
	}
	return out
}

// Rename sets a custom project name. Access is granted to the owner or a team member: the name is
// shared by the whole team, so anyone who sees the project may change it.
func (s *Service) Rename(ctx context.Context, id, userID, name string) *DeployError {
	name = strings.TrimSpace(name)
	if len([]rune(name)) > 80 {
		return derr("bad_input", "Имя проекта — до 80 символов.", "")
	}
	dep, _, err := s.repo.getFull(ctx, id)
	if err != nil {
		return derr("not_found", "Проект не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return derr("forbidden", "Нет доступа.", "")
	}
	if err := s.repo.SetNameByID(ctx, id, name); err != nil {
		return derr("not_found", "Проект не найден.", "")
	}
	if live := s.store.Get(id); live != nil {
		live.mu.Lock()
		live.Name = name
		live.mu.Unlock()
	}
	s.logTeam(ctx, dep, userID, "renamed")
	if name != "" {
		s.notifyTeamChange(ctx, dep, userID, "✏️ Проект «"+tgSpoiler(dep.Repo)+"» переименован в «"+tgSpoiler(name)+"»")
	}
	return nil
}

// RenameServer sets a custom server name per user and IP, visible to that user only.
func (s *Service) RenameServer(ctx context.Context, userID, ip, name string) *DeployError {
	name = strings.TrimSpace(name)
	if strings.TrimSpace(ip) == "" {
		return derr("bad_input", "Не указан сервер.", "")
	}
	if len([]rune(name)) > 80 {
		return derr("bad_input", "Имя сервера — до 80 символов.", "")
	}
	if err := s.repo.SetServerLabel(ctx, userID, ip, name); err != nil {
		return derr("server_error", "Не удалось сохранить имя сервера.", "")
	}
	return nil
}

// UpdateProtection changes the protected paths AND the trusted IP list of a running project.
// It works both with our VPN and with a VPN of the user's own (protection by IP alone). It
// rewrites the Caddy config, adjusts the client between split and full tunnel when our VPN is in
// use, and reloads Caddy gracefully.
func (s *Service) UpdateProtection(ctx context.Context, id, userID, pathsStr, ipsStr string) (*DeploymentView, *DeployError) {
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return nil, derr("not_found", "Проект не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return nil, derr("forbidden", "Нет доступа.", "")
	}
	if keyEnc == "" {
		return nil, derr("no_key", "Нет доступа к серверу.", "Разверни проект заново.")
	}
	key, de := s.decryptKey(keyEnc)
	if de != nil {
		return nil, de
	}
	dep.ServerState.VPNPaths = parsePathsStr(pathsStr)
	dep.ServerState.AllowedIPs = parseIPs(ipsStr)

	sshc, hkErr, err := dialKeyPinned(ctx, s.repo, dep.UserID, dep.ServerIP, dep.SSHUser, key)
	if hkErr != nil {
		return nil, hkErr
	}
	if err != nil {
		return nil, derr("ssh_failed", "Не удалось подключиться к серверу.", "Сервер недоступен.")
	}
	defer sshc.Close()
	dir := "/opt/djaploy/" + sanitizeName(dep.Repo)
	// In the gateway model the path protection lives in the site snippet inside the shared gateway.
	// We rewrite that snippet with the new paths and IPs and reload the shared Caddy with zero downtime.
	name := sanitizeName(dep.Repo)
	gw := "/opt/djaploy/_gateway"
	snippet := renderSiteSnippet(dep, name)
	if err := sshc.WriteFile(gw+"/sites/"+name+".caddy", snippet, "644"); err != nil {
		return nil, derr("update_failed", "Не удалось обновить конфиг сайта на сервере.", "Попробуй ещё раз.")
	}
	cmd := "(cd " + sq(gw) + " && docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile) 2>&1 || true"
	// for our own VPN, adjust the client between split and full tunnel (full when paths are protected)
	if dep.ServerState.VPN {
		allowed := "10.8.0.0/24"
		if len(dep.ServerState.VPNPaths) > 0 {
			allowed = "0.0.0.0/0"
		}
		cmd = "sed -i 's|^AllowedIPs = .*|AllowedIPs = " + allowed + "|' " + sq(dir+"/.djaploy/wg-client.conf") + " 2>/dev/null; " + cmd
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	_ = sshc.Run(cctx, cmd, func(string) {})
	cancel()

	_ = s.repo.SaveState(ctx, dep)
	if live := s.store.Get(id); live != nil {
		live.markState(func(st *ServerState) {
			st.VPNPaths = dep.ServerState.VPNPaths
			st.AllowedIPs = dep.ServerState.AllowedIPs
		})
	}
	s.logTeam(ctx, dep, userID, "protection_updated")
	s.notifyTeamChange(ctx, dep, userID, "🛡 Изменены закрытые разделы проекта «"+tgSpoiler(projectLabel(dep))+"»")
	v := dep.View()
	return &v, nil
}

// SetProjectTeam hands an existing project to a team, or makes it personal again with an empty
// teamID. Only the owner of the row may do it, and to hand it to a team they must be a member.
func (s *Service) SetProjectTeam(ctx context.Context, id, userID, teamID string) (*DeploymentView, *DeployError) {
	dep, _, err := s.repo.getFull(ctx, id)
	if err != nil {
		return nil, derr("not_found", "Проект не найден.", "")
	}
	if dep.UserID != userID {
		return nil, derr("forbidden", "Передать проект может только его владелец.", "")
	}
	if teamID != "" {
		if s.teams == nil {
			return nil, derr("forbidden", "Команды недоступны.", "")
		}
		if ok, err := s.teams.IsMember(ctx, teamID, userID); err != nil || !ok {
			return nil, derr("forbidden", "Ты не участник этой команды.", "")
		}
	}
	oldTeamID := dep.TeamID
	if err := s.repo.SetTeam(ctx, id, teamID); err != nil {
		return nil, derr("internal", "Не удалось изменить команду проекта.", "Попробуй ещё раз.")
	}
	dep.TeamID = teamID
	if live := s.store.Get(id); live != nil {
		live.mu.Lock()
		live.TeamID = teamID
		live.mu.Unlock()
	}

	// Notify the team and write to the feed, so handing a project over is not a surprise: a new
	// shared project takes a slot in the team limit.
	if teamID != "" && teamID != oldTeamID {
		if s.teams != nil {
			s.teams.LogActivity(ctx, teamID, userID, "project_added", dep.Repo)
		}
		if s.notifier != nil {
			s.notifier.NotifyTeamExcept(ctx, teamID, userID, "team",
				"📦 В команду передали проект «"+tgSpoiler(dep.Repo)+"» — теперь он общий и занимает место в лимите команды.")
		}
	}
	if teamID == "" && oldTeamID != "" {
		if s.teams != nil {
			s.teams.LogActivity(ctx, oldTeamID, userID, "project_removed", dep.Repo)
		}
		if s.notifier != nil {
			s.notifier.NotifyTeamExcept(ctx, oldTeamID, userID, "team",
				"📤 Проект «"+dep.Repo+"» убрали из команды — вернули в личные. Место в лимите освободилось.")
		}
	}

	v := dep.View()
	return &v, nil
}

// UpdateEnv rewrites the .env of a running project and restarts the containers so they pick the
// new variables up. We store no secrets: the file is written straight onto the user's server.
func (s *Service) UpdateEnv(ctx context.Context, id, userID, env string) (*DeploymentView, *DeployError) {
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return nil, derr("not_found", "Проект не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return nil, derr("forbidden", "Нет доступа.", "")
	}
	if keyEnc == "" {
		return nil, derr("no_key", "Нет доступа к серверу.", "Разверни проект заново.")
	}
	key, de := s.decryptKey(keyEnc)
	if de != nil {
		return nil, de
	}
	sshc, hkErr, err := dialKeyPinned(ctx, s.repo, dep.UserID, dep.ServerIP, dep.SSHUser, key)
	if hkErr != nil {
		return nil, hkErr
	}
	if err != nil {
		return nil, derr("ssh_failed", "Не удалось подключиться к серверу.", "Сервер недоступен.")
	}
	defer sshc.Close()
	dir := "/opt/djaploy/" + sanitizeName(dep.Repo)
	// a web project gets our domain block appended, a worker gets the .env as is
	content := env
	if !dep.IsWorker() {
		content = renderEnv(env, dep.Domain, dep.ServerState.Framework)
	}
	if err := sshc.WriteFile(dir+"/.env", content, "600"); err != nil {
		return nil, derr("update_failed", "Не удалось записать .env на сервере.", "Попробуй ещё раз.")
	}
	// Rebuild and force the containers to be recreated. A plain `up -d` is not enough: if the
	// application reads an .env that was baked into the image by a COPY step, which is common, the
	// new file never reaches it without a rebuild, and without --force-recreate compose may not
	// touch the container at all. The build cache keeps this fast.
	files := "-f docker-compose.yml -f docker-compose.caddy.yml"
	if dep.IsWorker() {
		files = "-f docker-compose.yml"
	}
	cmd := "cd " + sq(dir) + " && docker compose " + files + " up -d --build --force-recreate 2>&1 || true"
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	_ = sshc.Run(cctx, cmd, func(string) {})
	cancel()

	s.logTeam(ctx, dep, userID, "env_updated")
	s.notifyTeamChange(ctx, dep, userID, "🔑 Обновлён .env проекта «"+tgSpoiler(projectLabel(dep))+"» — контейнеры перезапущены")

	v := dep.View()
	return &v, nil
}

// isPublicIP reports an address routable on the internet (not loopback, private, link-local or
// otherwise reserved). It keeps a deploy from reaching into our own infrastructure network (SSRF).
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return true
}

func looksLikeDomain(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" || strings.ContainsAny(d, " /:\\") || !strings.Contains(d, ".") {
		return false
	}
	return true
}

func sanitizeName(full string) string {
	name := full
	if i := strings.LastIndex(full, "/"); i >= 0 {
		name = full[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "app"
	}
	return s
}
