package deploy

import (
	"strings"
	"sync"
	"time"
)

// Deploy statuses.
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusSuccess = "success"
	StatusFailed  = "failed"
)

// Log line kinds. The frontend colours lines by them.
const (
	KindOut   = "out"   // обычный вывод команды
	KindStep  = "step"  // начало шага
	KindOK    = "ok"    // успех
	KindError = "error" // ошибка
	KindDone  = "done"  // терминальная строка — поток лога закрывается
)

const (
	maxStoredLogs = 2000 // ограничение размера лога в БД
	maxLiveLogs   = 4000 // кап буфера логов в памяти — чтобы воркер не пух на «болтливых» сборках
)

type LogLine struct {
	Step string `json:"step"`
	Kind string `json:"kind"`
	Text string `json:"text"`
	TS   int64  `json:"ts"`
}

type StepState struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	Status string `json:"status"` // pending | running | done | failed
}

// ServerState records what our service has done on the user's server. It is the source of
// truth: the service always knows the server's current state and does not undo its own work.
type ServerState struct {
	ProjectType     string   `json:"project_type"`     // web (домен+Caddy+HTTPS) | worker (бот/воркер, без портов)
	Framework       string   `json:"framework"`        // django | other — Django-специфику (ALLOWED_HOSTS/CSRF/DEBUG, суперюзер) добавляем только для django
	Fail2ban        bool     `json:"fail2ban"`         // настроен fail2ban
	Docker          bool     `json:"docker"`           // установлен Docker
	RegistryMirrors bool     `json:"registry_mirrors"` // прописаны зеркала реестра
	Caddy           bool     `json:"caddy"`            // положен наш Caddy-слой (авто-HTTPS)
	AccessKey       bool     `json:"access_key"`       // установлен наш SSH-ключ доступа
	DeployUser      string   `json:"deploy_user"`      // непустой = деплоим под non-root юзером
	ProjectDir      string   `json:"project_dir"`      // где проект лежит на сервере
	VPN             bool     `json:"vpn"`              // поднят наш VPN-доступ (AmneziaWG)
	VPNPaths        []string `json:"vpn_paths"`        // пути, доступные только из VPN / с разрешённых IP (404 снаружи)
	AllowedIPs      []string `json:"allowed_ips"`      // доверенные IP/подсети к защищённым путям (свой VPN/офис юзера)
	Grafana         bool     `json:"grafana"`          // поднята Grafana на /grafana
	HostPort        int      `json:"host_port"`        // host-порт app для общего Caddy-gateway (мульти-сайт)
	GrafanaPort     int      `json:"grafana_port"`     // host-порт grafana для gateway (0 = нет)
	LastBuiltAt     string   `json:"last_built_at"`    // когда последний раз собирали/поднимали
	UpdatedAt       string   `json:"updated_at"`       // когда состояние обновлялось

	// CheckPath is what the uptime monitor pings. Empty = the site root (the way it always was).
	// A custom path helps when the home page is heavy (hits the database) or when you want to answer
	// 500 while degraded: the monitor treats anything below 500 as alive.
	CheckPath string `json:"check_path,omitempty"`
	// SkipDjangoTasks turns migrate/collectstatic off for deploys and redeploys. The flag is
	// inverted (false by default) so nothing changes for existing projects.
	SkipDjangoTasks bool `json:"skip_django_tasks,omitempty"`

	// Releases is the stack of successfully deployed commits (the last one is current). For rolling
	// back: a rollback pops the last entry and deploys the previous one.
	Releases []Release `json:"releases,omitempty"`
}

// Release is one successful release: a commit SHA and when it was deployed.
type Release struct {
	SHA string `json:"sha"`
	At  string `json:"at"`
}

// DeployError is a structured error: what happened (message) and what to change (hint).
type DeployError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

func (e *DeployError) Error() string { return e.Code + ": " + e.Message }

func derr(code, msg, hint string) *DeployError {
	return &DeployError{Code: code, Message: msg, Hint: hint}
}

func defaultSteps(withSuperuser, withVPN, nonRoot, worker, withDjango bool) []StepState {
	var steps []StepState
	if worker {
		// worker or bot: no domain, no ports, no Caddy and no HTTP check
		steps = []StepState{
			{Key: "connect", Title: "SSH-подключение", Status: "pending"},
			{Key: "prepare", Title: "Подготовка сервера", Status: "pending"},
			{Key: "docker", Title: "Docker", Status: "pending"},
			{Key: "clone", Title: "Клон репозитория", Status: "pending"},
			{Key: "env", Title: ".env", Status: "pending"},
			{Key: "up", Title: "Сборка и запуск", Status: "pending"},
		}
		if withDjango {
			steps = append(steps, StepState{Key: "django", Title: "Django: миграции и статика", Status: "pending"})
		}
	} else {
		steps = []StepState{
			{Key: "dns", Title: "DNS", Status: "pending"},
			{Key: "connect", Title: "SSH-подключение", Status: "pending"},
			{Key: "prepare", Title: "Подготовка сервера", Status: "pending"},
			{Key: "docker", Title: "Docker", Status: "pending"},
			{Key: "clone", Title: "Клон репозитория", Status: "pending"},
			{Key: "env", Title: ".env", Status: "pending"},
			{Key: "caddy", Title: "Caddy / HTTPS", Status: "pending"},
			{Key: "up", Title: "Сборка и запуск", Status: "pending"},
		}
		if withDjango {
			steps = append(steps, StepState{Key: "django", Title: "Django: миграции и статика", Status: "pending"})
		}
		steps = append(steps, StepState{Key: "health", Title: "Проверка", Status: "pending"})
	}
	// optional soft steps, run after a successful deploy and never failing it
	if withSuperuser {
		steps = append(steps, StepState{Key: "superuser", Title: "Суперпользователь", Status: "pending"})
	}
	if withVPN {
		steps = append(steps, StepState{Key: "vpn", Title: "VPN-доступ", Status: "pending"})
	}
	if nonRoot {
		steps = append(steps, StepState{Key: "nonroot", Title: "Отдельный пользователь", Status: "pending"})
	}
	return steps
}

// Deployment is the state of one deploy plus its log buffer and its subscribers (SSE).
// Secrets (password, .env, token) are NOT kept here, only in the job inside the worker's memory.
type Deployment struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	TeamID   string `json:"team_id,omitempty"` // непустой = проект команды (виден всем участникам)
	Repo     string `json:"repo"`
	Provider string `json:"provider"` // github | gitlab — откуда клоним и как получаем токен
	Name     string `json:"name"`     // кастомное имя проекта (пусто → показываем домен/repo)
	Domain   string `json:"domain"`
	ServerIP string `json:"server_ip"`

	AppService   string `json:"app_service"`
	AppPort      int    `json:"app_port"`
	ServeStatic  bool   `json:"serve_static"` // Caddy раздаёт /static из volume (иначе — статика в S3/у app)
	ServeMedia   bool   `json:"serve_media"`  // Caddy раздаёт /media из volume (отдельно от static — бывает медиа в S3)
	StaticVolume string `json:"static_volume"`
	MediaVolume  string `json:"media_volume"`
	HasSuperuser bool   `json:"has_superuser"`

	SSHUser   string `json:"ssh_user"`
	CDEnabled bool   `json:"cd_enabled"`
	Health    string `json:"health"` // up|down|"" — живое здоровье сайта (пишет монитор аптайма)

	ServerState ServerState `json:"server_state"`

	Status    string       `json:"status"`
	Steps     []StepState  `json:"steps"`
	Err       *DeployError `json:"error,omitempty"`
	URL       string       `json:"url,omitempty"`
	CreatedAt time.Time    `json:"created_at"`

	mu        sync.Mutex
	logs      []LogLine
	subs      map[chan LogLine]struct{}
	done      bool
	sshKeyEnc string // зашифрованный приватный ключ доступа (для редеплоя/CD)
}

// Repository providers. An empty value in old rows means github.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
)

// Frameworks: django gets the Django specifics (env variables, superuser), other gets none.
// An empty value in old rows means django (backwards compatibility).
const (
	frameworkDjango = "django"
	frameworkOther  = "other"
)

// frameworkOrDefault: empty means django (older projects were Django centric).
func frameworkOrDefault(f string) string {
	if f == frameworkOther {
		return frameworkOther
	}
	return frameworkDjango
}

func providerOrDefault(p string) string {
	if p == ProviderGitLab {
		return ProviderGitLab
	}
	return ProviderGitHub
}

// IsGitLab reports that the repository lives on GitLab (different clone URL, token, webhook).
func (d *Deployment) IsGitLab() bool {
	return d.Provider == ProviderGitLab
}

// IsWorker reports a worker or bot project (no domain, ports, Caddy or HTTPS).
func (d *Deployment) IsWorker() bool {
	return d.ServerState.ProjectType == "worker"
}

// RunsDjangoTasks reports whether migrate + collectstatic should run. Only for Django and only if
// the user has not turned them off in project settings: not everyone needs migrations on every
// deploy, and the step costs time.
func (d *Deployment) RunsDjangoTasks() bool {
	return frameworkOrDefault(d.ServerState.Framework) == frameworkDjango && !d.ServerState.SkipDjangoTasks
}

// CheckURL is what the uptime monitor pings: the whole site or the path the user set.
func (d *Deployment) CheckURL() string {
	p := d.ServerState.CheckPath
	if p == "" {
		return d.URL
	}
	return strings.TrimSuffix(d.URL, "/") + p
}

// HasKey reports whether we have a stored access key (redeploy and CD can run without a password).
func (d *Deployment) HasKey() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sshKeyEnc != ""
}

// DeploymentView is a JSON snapshot (no mutex, channels or logs) that is safe to send out.
type DeploymentView struct {
	ID           string       `json:"id"`
	TeamID       string       `json:"team_id,omitempty"`
	Repo         string       `json:"repo"`
	Provider     string       `json:"provider"`
	Name         string       `json:"name"`
	Domain       string       `json:"domain"`
	ServerIP     string       `json:"server_ip"`
	AppService   string       `json:"app_service"`
	AppPort      int          `json:"app_port"`
	ServeStatic  bool         `json:"serve_static"`
	ServeMedia   bool         `json:"serve_media"`
	HasSuperuser bool         `json:"has_superuser"`
	Path         string       `json:"path"` // где проект лежит на сервере юзера
	CDEnabled    bool         `json:"cd_enabled"`
	CanRedeploy  bool         `json:"can_redeploy"` // есть ключ доступа → редеплой/CD без пароля
	CanRollback  bool         `json:"can_rollback"` // есть предыдущая версия в истории → можно откатить
	SSHUser      string       `json:"ssh_user"`
	Health       string       `json:"health"`       // up|down|"" — живое здоровье (монитор аптайма)
	ServerState  ServerState  `json:"server_state"` // что наш сервис сделал на сервере
	Status       string       `json:"status"`
	Steps        []StepState  `json:"steps"`
	Err          *DeployError `json:"error,omitempty"`
	URL          string       `json:"url,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
}

func (d *Deployment) View() DeploymentView {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DeploymentView{
		ID: d.ID, TeamID: d.TeamID, Repo: d.Repo, Provider: providerOrDefault(d.Provider), Name: d.Name, Domain: d.Domain, ServerIP: d.ServerIP,
		AppService: d.AppService, AppPort: d.AppPort, ServeStatic: d.ServeStatic, ServeMedia: d.ServeMedia,
		HasSuperuser: d.HasSuperuser, Path: "/opt/djaploy/" + sanitizeName(d.Repo),
		CDEnabled: d.CDEnabled, CanRedeploy: d.sshKeyEnc != "",
		CanRollback: canRollback(d.sshKeyEnc, d.Status, len(d.ServerState.Releases)),
		SSHUser:     d.SSHUser, Health: d.Health, ServerState: d.ServerState,
		Status: d.Status, Steps: append([]StepState(nil), d.Steps...),
		Err: d.Err, URL: d.URL, CreatedAt: d.CreatedAt,
	}
}

// canRollback reports whether a rollback is possible: it needs an access key and a working
// version in history. If the last deploy failed, rollback restores the last working one, so a
// single release is enough; if it succeeded, rollback steps one version back and needs two.
func canRollback(keyEnc, status string, releases int) bool {
	if keyEnc == "" {
		return false
	}
	if status == StatusFailed {
		return releases >= 1
	}
	return releases >= 2
}

// markState atomically updates the server state (what we did) and its timestamp.
func (d *Deployment) markState(f func(*ServerState)) {
	d.mu.Lock()
	f(&d.ServerState)
	d.ServerState.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	d.mu.Unlock()
}

func (d *Deployment) log(step, kind, text string) {
	d.mu.Lock()
	l := LogLine{Step: step, Kind: kind, Text: text, TS: time.Now().UnixMilli()}
	d.logs = append(d.logs, l)
	if len(d.logs) > maxLiveLogs { // держим только хвост — память под контролем
		d.logs = append([]LogLine(nil), d.logs[len(d.logs)-maxLiveLogs:]...)
	}
	for ch := range d.subs {
		select {
		case ch <- l:
		default: // подписчик не успевает — пропускаем строку, чтобы не блокировать деплой
		}
	}
	d.mu.Unlock()
}

func (d *Deployment) setStatus(s string)      { d.mu.Lock(); d.Status = s; d.mu.Unlock() }
func (d *Deployment) setError(e *DeployError) { d.mu.Lock(); d.Err = e; d.mu.Unlock() }
func (d *Deployment) setURL(u string)         { d.mu.Lock(); d.URL = u; d.mu.Unlock() }

func (d *Deployment) setStep(key, status string) {
	d.mu.Lock()
	for i := range d.Steps {
		if d.Steps[i].Key == key {
			d.Steps[i].Status = status
			break
		}
	}
	d.mu.Unlock()
}

// finish marks the deploy as complete and sends the terminal line that closes the SSE stream.
func (d *Deployment) finish() {
	d.mu.Lock()
	d.done = true
	d.mu.Unlock()
	d.log("", KindDone, "")
}

// LogsSnapshot copies the logs for persistence, at most the last maxStoredLogs lines.
func (d *Deployment) LogsSnapshot() []LogLine {
	d.mu.Lock()
	defer d.mu.Unlock()
	src := d.logs
	if len(src) > maxStoredLogs {
		src = src[len(src)-maxStoredLogs:]
	}
	return append([]LogLine(nil), src...)
}

func (d *Deployment) Subscribe() (chan LogLine, []LogLine) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ch := make(chan LogLine, 256)
	if d.subs == nil {
		d.subs = map[chan LogLine]struct{}{}
	}
	d.subs[ch] = struct{}{}
	history := append([]LogLine(nil), d.logs...)
	if d.done {
		history = append(history, LogLine{Kind: KindDone})
	}
	return ch, history
}

func (d *Deployment) Unsubscribe(ch chan LogLine) {
	d.mu.Lock()
	if _, ok := d.subs[ch]; ok {
		delete(d.subs, ch)
		close(ch)
	}
	d.mu.Unlock()
}

// Store is the in-memory registry of LIVE deploys (for SSE). History lives in the database (repo).
type Store struct {
	mu sync.RWMutex
	m  map[string]*Deployment
}

func NewStore() *Store { return &Store{m: map[string]*Deployment{}} }

func (s *Store) Add(d *Deployment) {
	s.mu.Lock()
	s.m[d.ID] = d
	s.mu.Unlock()
}

func (s *Store) Get(id string) *Deployment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[id]
}

// BusyOn reports whether a deploy is running on this server right now (for this owner). Needed so we
// never revoke access or delete a project out from under a running deploy.
func (s *Store) BusyOn(userID, ip string) bool {
	s.mu.RLock()
	live := make([]*Deployment, 0, len(s.m))
	for _, d := range s.m {
		live = append(live, d)
	}
	s.mu.RUnlock()
	for _, d := range live {
		if d.UserID != userID || d.ServerIP != ip {
			continue
		}
		d.mu.Lock()
		busy := d.Status == StatusQueued || d.Status == StatusRunning
		d.mu.Unlock()
		if busy {
			return true
		}
	}
	return false
}

func (s *Store) Remove(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}
