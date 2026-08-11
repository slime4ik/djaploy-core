package deploy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Deployer runs the deploy steps on the user's server over one SSH connection.
type Deployer struct {
	ssh         *SSH
	j           *job
	dep         *Deployment
	repo        *Repo
	encKey      []byte
	token       string // GitHub installation token, used by git clone/fetch
	dir         string // /opt/djaploy/<name>
	needSudo    bool   // logged in as non-root, so system steps go through sudo
	rollbackSHA string // non-empty means rollback: deploy this commit instead of HEAD
}

// priv wraps a script so it runs with root rights. As root the script is left as is,
// otherwise it goes through `sudo -S` (the password on stdin is the ssh password; with
// NOPASSWD it is simply ignored).
func (d *Deployer) priv(script string) string {
	if !d.needSudo || d.j == nil {
		return script
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	return "printf '%s\\n' " + sq(d.j.sshPassword) + " | sudo -S -p '' bash -c \"$(printf %s " + sq(b64) + " | base64 -d)\""
}

// writeFile writes a file. As root it writes directly, otherwise into a temp file that is
// moved into place with sudo.
func (d *Deployer) writeFile(path, content, mode string) error {
	if !d.needSudo {
		return d.ssh.WriteFile(path, content, mode)
	}
	tmp := "/tmp/.djaploy_" + itoa(int(time.Now().UnixNano()&0xffffff))
	if err := d.ssh.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	script := "mkdir -p " + sq(filepath.Dir(path)) + " && mv " + sq(tmp) + " " + sq(path) + " && chmod " + mode + " " + sq(path)
	return d.ssh.Run(ctx, d.priv(script), func(string) {})
}

// sshCapture runs a command and returns the collected output (used to detect root/sudo).
func sshCapture(sshc *SSH, cmd string) string {
	var b strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = sshc.Run(ctx, cmd, func(l string) { b.WriteString(l); b.WriteByte('\n') })
	return strings.TrimSpace(b.String())
}

// gitlabBaseURL is the clone base for gitlab repositories, overridden from config in NewService.
var gitlabBaseURL = "https://gitlab.com"

// cloneURL is the HTTPS address of the repository for its provider.
func cloneURL(d *Deployment) string {
	if d.IsGitLab() {
		return strings.TrimRight(gitlabBaseURL, "/") + "/" + d.Repo + ".git"
	}
	return "https://github.com/" + d.Repo + ".git"
}

// gitAuth builds the authorization flag for git commands. An empty token (the public demo
// repository, cloned anonymously) means no header at all. The basic-auth login depends on the
// provider: GitHub expects x-access-token, GitLab expects oauth2.
func gitAuth(provider, token string) string {
	if token == "" {
		return ""
	}
	login := "x-access-token"
	if provider == ProviderGitLab {
		login = "oauth2"
	}
	basic := base64.StdEncoding.EncodeToString([]byte(login + ":" + token))
	return "-c http.extraheader=" + sq("AUTHORIZATION: basic "+basic) + " "
}

// runDeployment is the whole cycle: DNS, then SSH, then the steps. Logs stream into dep and
// errors are structured.
func runDeployment(ctx context.Context, repo *Repo, encKey []byte, j *job) {
	dep := j.dep
	dep.setStatus(StatusRunning)
	persist(repo, dep, false)

	// 1. DNS before SSH, so we can point at the A record right away. A worker or bot has no
	// domain, so it is skipped.
	if !dep.IsWorker() {
		dep.setStep("dns", "running")
		dep.log("dns", KindStep, "Проверяю DNS: "+dep.Domain+" → "+dep.ServerIP)
		if de := checkDNS(dep.Domain, dep.ServerIP); de != nil {
			failStep(repo, dep, "dns", de)
			return
		}
		dep.setStep("dns", "done")
		dep.log("dns", KindOK, "DNS ок")
		persist(repo, dep, false)
	}

	// 2. SSH connection (root plus password).
	dep.setStep("connect", "running")
	dep.log("connect", KindStep, "Подключаюсь по SSH: "+j.sshUser+"@"+dep.ServerIP)
	sshc, hkErr, err := dialPasswordPinned(ctx, repo, dep.UserID, dep.ServerIP, j.sshUser, j.sshPassword)
	if hkErr != nil {
		failStep(repo, dep, "connect", hkErr)
		return
	}
	if err != nil {
		failStep(repo, dep, "connect", derr("ssh_failed",
			"Не удалось подключиться по SSH к "+dep.ServerIP+".",
			"Проверь: IP верный, пароль от «"+j.sshUser+"» верный, порт 22 открыт, и на сервере разрешён вход по паролю (sshd_config: PasswordAuthentication yes)."))
		return
	}
	defer sshc.Close()
	dep.setStep("connect", "done")
	dep.log("connect", KindOK, "Подключился")
	persist(repo, dep, false)

	d := &Deployer{ssh: sshc, j: j, dep: dep, repo: repo, encKey: encKey, token: j.token, dir: "/opt/djaploy/" + j.name}

	// not logged in as root? many VPS providers hand out a sudo user instead, so we escalate.
	if sshCapture(sshc, "id -u") != "0" {
		d.needSudo = true
		if sshCapture(sshc, "printf '%s\\n' "+sq(j.sshPassword)+" | sudo -S -p '' id -u 2>&1") != "0" {
			failStep(repo, dep, "connect", derr("no_sudo",
				"Вход выполнен не под root, и sudo не сработал для «"+j.sshUser+"».",
				"Дай этому пользователю sudo (визард: usermod -aG sudo "+j.sshUser+"), либо укажи root и его пароль."))
			return
		}
		dep.log("connect", KindOut, "Вход не под root — системные шаги пойдут через sudo")
	}

	// install our SSH key for future password-less redeploys and CD (quiet, never fails a deploy)
	d.installAccessKey()

	type stepDef struct {
		key     string
		timeout time.Duration
		soft    bool // a soft step never fails the deploy, the project already runs
		fn      func(context.Context) *DeployError
	}
	isDjango := frameworkOrDefault(dep.ServerState.Framework) == frameworkDjango
	var steps []stepDef
	if dep.IsWorker() {
		// worker or bot: no Caddy and no HTTP check, we just build and start compose
		steps = []stepDef{
			{"prepare", 8 * time.Minute, false, d.prepareServer},
			{"docker", 8 * time.Minute, false, d.ensureDocker},
			{"clone", 4 * time.Minute, false, d.clone},
			{"env", 1 * time.Minute, false, d.writeEnv},
			{"up", 18 * time.Minute, false, d.composeUp},
		}
		if isDjango {
			steps = append(steps, stepDef{"django", 5 * time.Minute, true, d.djangoTasks})
		}
	} else {
		steps = []stepDef{
			{"prepare", 8 * time.Minute, false, d.prepareServer},
			{"docker", 8 * time.Minute, false, d.ensureDocker},
			{"clone", 4 * time.Minute, false, d.clone},
			{"env", 1 * time.Minute, false, d.writeEnv},
			{"caddy", 5 * time.Minute, false, d.setupGateway}, // shared Caddy gateway (multi-site)
			{"up", 18 * time.Minute, false, d.composeUp},
		}
		// Django: migrate and collectstatic run BEFORE health, so the site is checked migrated.
		if isDjango {
			steps = append(steps, stepDef{"django", 5 * time.Minute, true, d.djangoTasks})
		}
		steps = append(steps, stepDef{"health", 3 * time.Minute, false, d.health})
	}
	if j.createSU {
		steps = append(steps, stepDef{"superuser", 2 * time.Minute, true, d.createSuperuser})
	}
	// VPN goes before non-root: it writes the client config into the project, and the handover
	// then passes that config on to the deploy user.
	if j.enableVPN {
		steps = append(steps, stepDef{"vpn", 10 * time.Minute, true, d.provisionVPN})
	}
	if j.nonRoot {
		steps = append(steps, stepDef{"nonroot", 3 * time.Minute, true, d.handoverNonRoot})
	}
	for _, st := range steps {
		select {
		case <-ctx.Done():
			failStep(repo, dep, st.key, derr("timeout", "Деплой прерван по общему таймауту.", "Попробуй ещё раз."))
			return
		default:
		}
		dep.setStep(st.key, "running")
		persist(repo, dep, false)

		sctx, cancel := context.WithTimeout(ctx, st.timeout)
		de := st.fn(sctx)
		cancel()

		if de != nil {
			// soft step: the project is already up, so we warn and move on instead of failing
			if st.soft {
				dep.setStep(st.key, "done")
				dep.log(st.key, KindError, de.Message)
				if de.Hint != "" {
					dep.log(st.key, KindError, "→ "+de.Hint)
				}
				persist(repo, dep, false)
				continue
			}
			// a timeout on one step gets a clearer hint
			if sctx.Err() == context.DeadlineExceeded && de.Code != "bad_input" {
				de = derr("step_timeout",
					"Шаг «"+stepTitle(dep, st.key)+"» не уложился в отведённое время и был прерван.",
					"Чаще всего это зависший apt/сборка. Проверь сервер и попробуй ещё раз.")
			}
			failStep(repo, dep, st.key, de)
			return
		}
		dep.setStep(st.key, "done")
		persist(repo, dep, false)
	}

	// We logged in as non-root and did not hand over to a separate user, so the project goes to
	// the login user (docker group plus folder ownership) and redeploy/CD run by key without sudo.
	if d.needSudo && dep.ServerState.DeployUser == "" {
		fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		script := "usermod -aG docker " + sq(j.sshUser) + " || true; chown -R " + sq(j.sshUser) + " " + sq(d.dir) +
			"; chown -R " + sq(j.sshUser) + " /opt/djaploy/_gateway 2>/dev/null || true"
		if err := d.ssh.Run(fctx, d.priv(script), func(string) {}); err != nil {
			dep.log("", KindOut, "(не удалось передать проект юзеру "+j.sshUser+" — редеплой может потребовать root)")
		}
		cancel()
	}

	d.recordRelease() // remember the deployed commit so we can roll back to this version
	if dep.IsWorker() {
		dep.log("", KindOK, "Готово ✓  Контейнеры собраны и запущены на сервере")
	} else {
		dep.setURL("https://" + dep.Domain)
		dep.log("", KindOK, "Готово ✓  https://"+dep.Domain)
	}
	dep.setStatus(StatusSuccess)
	persist(repo, dep, true)
	dep.finish()
}

func failStep(repo *Repo, dep *Deployment, step string, de *DeployError) {
	dep.setStep(step, "failed")
	dep.setError(de)
	dep.setStatus(StatusFailed)
	dep.log(step, KindError, de.Message)
	if de.Hint != "" {
		dep.log(step, KindError, "→ "+de.Hint)
	}
	persist(repo, dep, true)
	dep.finish()
}

// persist writes state to the database; final=true stores the logs as well. A failed write
// here never fails the deploy.
func persist(repo *Repo, dep *Deployment, final bool) {
	if repo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if final {
		err = repo.SaveFinal(ctx, dep)
	} else {
		err = repo.SaveState(ctx, dep)
	}
	if err != nil {
		dep.log("", KindOut, "(не удалось сохранить состояние в БД: "+trim(err.Error())+")")
	}
}

func stepTitle(dep *Deployment, key string) string {
	for _, s := range dep.Steps {
		if s.Key == key {
			return s.Title
		}
	}
	return key
}

// run executes a step command and streams it into the log (escalating rights when we are not root).
func (d *Deployer) run(ctx context.Context, key, cmd string) error {
	return d.ssh.Run(ctx, d.priv(cmd), func(line string) {
		d.dep.log(key, KindOut, line)
	})
}

// STEP 1: server prep, apt and fail2ban.
func (d *Deployer) prepareServer(ctx context.Context) *DeployError {
	d.dep.log("prepare", KindStep, "Обновляю пакеты и ставлю fail2ban…")
	script := `set -e
export DEBIAN_FRONTEND=noninteractive
# DPkg::Lock::Timeout=300 makes apt WAIT for the lock up to 5 minutes (on a fresh server the
# background apt-daily/unattended-upgrades holds it) instead of failing with "Could not get lock".
# We also do not fail when a THIRD-PARTY repository is broken (a stale PPA, say): the packages we
# need live in the main Ubuntu repository, which is reachable. We report it and move on.
apt-get -o DPkg::Lock::Timeout=300 update -y || echo "(apt-get update частично не прошёл — вероятно сторонний репозиторий; продолжаю)"
apt-get -o DPkg::Lock::Timeout=300 install -y -o Dpkg::Options::=--force-confnew fail2ban curl ca-certificates git
cat > /etc/fail2ban/jail.local <<'INI'
[sshd]
enabled = true
maxretry = 5
bantime = 1h
INI
systemctl enable --now fail2ban
systemctl restart fail2ban
# open HTTP/HTTPS on the local firewall (Caddy and Let's Encrypt need it). Cloud firewalls are separate.
if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp >/dev/null 2>&1 || true; ufw allow 443/tcp >/dev/null 2>&1 || true; fi
echo "Сервер подготовлен, fail2ban активен."`
	if err := d.run(ctx, "prepare", script); err != nil {
		return derr("prepare_failed",
			"Не удалось подготовить сервер (apt/fail2ban).",
			"Нужен Ubuntu/Debian с systemd и доступом в интернет. Смотри лог выше — там точная строка.")
	}
	d.dep.markState(func(s *ServerState) { s.Fail2ban = true })
	return nil
}

// STEP 1 (docker): docker itself plus registry mirrors.
func (d *Deployer) ensureDocker(ctx context.Context) *DeployError {
	d.dep.log("docker", KindStep, "Проверяю Docker и зеркала реестра…")
	script := `set -e
# On fresh servers apt auto-updates run in the background (unattended-upgrades / apt-daily) and
# hold the lock, so installing Docker (apt again) fails with "Could not get lock". We wait for the
# background apt to release it (up to ~5 min). No fuser on the box means we just carry on.
i=0
while command -v fuser >/dev/null 2>&1 && fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -gt 60 ] && { echo "apt-замок всё ещё занят — продолжаю, может не пройти"; break; }
  echo "жду фоновое обновление apt (держит замок)…"; sleep 5
done
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker не найден — устанавливаю…"
  curl -fsSL https://get.docker.com | sh
fi
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{ "registry-mirrors": ["https://mirror.gcr.io", "https://dockerhub.timeweb.cloud"], "userland-proxy": false, "dns": ["8.8.8.8", "1.1.1.1"] }
JSON
systemctl restart docker || true
docker compose version >/dev/null 2>&1 || { echo "плагин docker compose недоступен"; exit 42; }
echo "Docker готов."`
	if err := d.run(ctx, "docker", script); err != nil {
		return derr("docker_failed",
			"Не удалось подготовить Docker на сервере.",
			"Если в логе «Could not get lock … apt-get» — на сервере шло фоновое обновление (apt-daily/unattended-upgrades). Подожди минуту и повтори деплой. Иначе — проверь интернет на сервере и что ОС это Ubuntu/Debian.")
	}
	d.dep.markState(func(s *ServerState) { s.Docker = true; s.RegistryMirrors = true })
	return nil
}

// STEP 2: clone the repository (the token goes into http.extraheader, never into the URL or the log).
func (d *Deployer) clone(ctx context.Context) *DeployError {
	d.dep.log("clone", KindStep, "Клонирую "+d.dep.Repo+"…")
	script := fmt.Sprintf(`set -e
mkdir -p /opt/djaploy
rm -rf %q
git %sclone --depth 1 %q %q
test -f %q/docker-compose.yml || test -f %q/compose.yml || { echo "NO_COMPOSE"; exit 7; }
echo "Репозиторий на месте."`, d.dir, gitAuth(d.dep.Provider, d.j.token), cloneURL(d.dep), d.dir, d.dir, d.dir)
	if err := d.run(ctx, "clone", script); err != nil {
		accessHint := "приложение имеет доступ к репозиторию (кнопка «Управление» на дашборде)"
		if d.dep.IsGitLab() {
			accessHint = "GitLab привязан к аккаунту (настройки) и у тебя есть доступ к проекту"
		}
		return derr("clone_failed",
			"Не удалось склонировать репозиторий или в его корне нет docker-compose.yml.",
			"Проверь: 1) "+accessHint+"; 2) в корне репо есть docker-compose.yml с сервисом «"+d.dep.AppService+"» на порту "+itoa(d.dep.AppPort)+".")
	}
	d.dep.markState(func(s *ServerState) { s.ProjectDir = d.dir })
	return nil
}

// STEP 3: the application .env plus our domain variables.
func (d *Deployer) writeEnv(_ context.Context) *DeployError {
	d.dep.log("env", KindStep, "Пишу .env (твой + доменные переменные)…")
	if err := d.writeFile(d.dir+"/.env", renderEnv(d.j.env, d.dep.Domain, d.dep.ServerState.Framework), "600"); err != nil {
		return derr("env_failed", "Не удалось записать .env на сервер.",
			"Похоже на нехватку прав или места на диске сервера.")
	}
	return nil
}

// STEP 5: build and start.
func (d *Deployer) composeUp(ctx context.Context) *DeployError {
	d.dep.log("up", KindStep, "Собираю образы и поднимаю контейнеры (это самый долгий шаг)…")
	// worker or bot: only the user's compose, without our Caddy overlay
	composeFiles := "-f docker-compose.yml -f docker-compose.caddy.yml"
	hint := "Чаще всего: ошибка в Dockerfile/requirements приложения, либо сервис в compose назван не «" + d.dep.AppService + "» / не слушает " + itoa(d.dep.AppPort) + ". Смотри лог сборки выше — там точная строка."
	if d.dep.IsWorker() {
		composeFiles = "-f docker-compose.yml"
		hint = "Чаще всего: ошибка в Dockerfile/requirements приложения. Смотри лог сборки выше — там точная строка."
	}
	cmd := fmt.Sprintf(`cd %q && docker compose %s up -d --build --remove-orphans 2>&1`, d.dir, composeFiles)
	var buf strings.Builder
	err := d.ssh.Run(ctx, d.priv(cmd), func(line string) {
		d.dep.log("up", KindOut, line)
		buf.WriteString(line)
		buf.WriteByte('\n')
	})
	if err != nil {
		// A network failure (we could not reach repositories or registries) gets its own message:
		// that is a limit of the server's network (common on RU servers), not a bug in the user's code.
		if isNetworkErr(buf.String()) {
			return derr("build_network",
				"Сборка упала из-за СЕТИ сервера, а не твоего кода — не удалось скачать пакеты или образы.",
				netErrHint())
		}
		return derr("build_failed", "Сборка или запуск контейнеров упали.", hint)
	}
	d.dep.markState(func(s *ServerState) { s.LastBuiltAt = time.Now().UTC().Format(time.RFC3339) })
	// Web project: the app is up, so we attach it to the shared gateway network by alias for Caddy
	// to reach it. Doing it here covers deploy, redeploy and rollback at once (all call composeUp).
	if !d.dep.IsWorker() {
		if de := d.connectGateway(ctx); de != nil {
			return de
		}
	}
	return nil
}

// recordRelease stores the currently deployed commit in the release history (for rollback).
func (d *Deployer) recordRelease() {
	sha := captureCommit(d.ssh, d.dir)
	if sha == "" {
		return
	}
	d.dep.markState(func(s *ServerState) {
		if n := len(s.Releases); n > 0 && s.Releases[n-1].SHA == sha {
			return // the same commit is already on top, no duplicate
		}
		s.Releases = append(s.Releases, Release{SHA: sha, At: time.Now().UTC().Format(time.RFC3339)})
		if len(s.Releases) > 10 { // keep only the last 10 versions
			s.Releases = append([]Release(nil), s.Releases[len(s.Releases)-10:]...)
		}
	})
}

// rollbackCheckout is the rollback itself: fetch one specific commit and switch to it.
// The .env file and the volumes (data and database) are left untouched.
func (d *Deployer) rollbackCheckout(ctx context.Context) *DeployError {
	d.dep.log("rollback", KindStep, "Откатываю код на предыдущую версию ("+shortSHA(d.rollbackSHA)+")…")
	script := "set -e\ncd " + sq(d.dir) + "\n" +
		"git " + gitAuth(d.dep.Provider, d.token) + "fetch --depth 1 origin " + sq(d.rollbackSHA) + "\n" +
		"git checkout -f " + sq(d.rollbackSHA) + "\n" +
		"echo 'Код откатан на " + shortSHA(d.rollbackSHA) + "'"
	if err := d.run(ctx, "rollback", script); err != nil {
		return derr("rollback_failed",
			"Не удалось откатить код на предыдущую версию.",
			"Возможно, этот коммит уже недоступен в репозитории, или приложение потеряло доступ к репо.")
	}
	return nil
}

// captureCommit reads the project's current commit SHA on the server (git rev-parse HEAD).
func captureCommit(sshc *SSH, dir string) string {
	out := sshCapture(sshc, "cd "+sq(dir)+" && git rev-parse HEAD 2>/dev/null")
	for _, tok := range strings.Fields(out) {
		if isHexSHA(tok) {
			return tok
		}
	}
	return ""
}

func isHexSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// installAccessKey generates an ed25519 key, puts the public half into the server's
// authorized_keys, encrypts the private half and stores it in the database, so redeploys and CD
// run without the user's password. It stays quiet: if anything fails the deploy is unaffected,
// there is just no automatic redeploy.
func (d *Deployer) installAccessKey() {
	if len(d.encKey) == 0 {
		return
	}
	priv, authLine, err := genSSHKey()
	if err != nil {
		d.dep.log("connect", KindOut, "(ключ доступа не сгенерён: "+trim(err.Error())+")")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && " +
		"grep -qF " + sq(authLine) + " ~/.ssh/authorized_keys || echo " + sq(authLine) + " >> ~/.ssh/authorized_keys && " +
		"chmod 600 ~/.ssh/authorized_keys"
	if err := d.ssh.Run(ctx, cmd, func(string) {}); err != nil {
		d.dep.log("connect", KindOut, "(не удалось установить ключ доступа — авто-редеплой будет недоступен)")
		return
	}
	enc, err := encrypt(d.encKey, priv)
	if err != nil {
		return
	}
	d.dep.mu.Lock()
	d.dep.sshKeyEnc = enc
	d.dep.mu.Unlock()
	d.dep.markState(func(s *ServerState) { s.AccessKey = true })
	if d.repo != nil {
		c, cc := context.WithTimeout(context.Background(), 5*time.Second)
		_ = d.repo.SaveSSHKey(c, d.dep.ID, enc)
		cc()
	}
	d.dep.log("connect", KindOK, "Ключ доступа установлен — повторные деплои пойдут без пароля")
}

// STEP 7 (optional): create a Django superuser. Soft, so it never fails the deploy.
func (d *Deployer) createSuperuser(ctx context.Context) *DeployError {
	d.dep.log("superuser", KindStep, "Создаю суперпользователя Django…")
	// idempotent: createsuperuser --noinput driven by env (DJANGO_SUPERUSER_*)
	cmd := fmt.Sprintf(`cd %q && docker compose -f docker-compose.yml -f docker-compose.caddy.yml exec -T `+
		`-e DJANGO_SUPERUSER_USERNAME=%s -e DJANGO_SUPERUSER_EMAIL=%s -e DJANGO_SUPERUSER_PASSWORD=%s `+
		`%s python manage.py createsuperuser --noinput 2>&1`,
		d.dir, sq(d.j.suUsername), sq(d.j.suEmail), sq(d.j.suPassword), sq(d.dep.AppService))
	if err := d.run(ctx, "superuser", cmd); err != nil {
		return derr("superuser_failed",
			"Проект развёрнут и работает, но суперпользователя создать не вышло.",
			"Обычно это значит, что такой пользователь уже есть, либо в сервисе «"+d.dep.AppService+"» нет manage.py. Можно создать вручную: docker compose exec "+d.dep.AppService+" python manage.py createsuperuser")
	}
	d.dep.log("superuser", KindOK, "Суперпользователь «"+d.j.suUsername+"» создан")
	return nil
}

// composeFiles is the -f set for docker compose (a web project adds our Caddy overlay, a worker
// does not).
func (d *Deployer) composeFiles() string {
	if d.dep.IsWorker() {
		return "-f docker-compose.yml"
	}
	return "-f docker-compose.yml -f docker-compose.caddy.yml"
}

// STEP (optional, soft): Django migrations and static files. The user does not have to put
// migrate/collectstatic into their own docker-compose, djaploy runs both on every deploy and
// redeploy.
//
// makemigrations is DELIBERATELY not run here. It generates new migration files out of model
// changes, and on the server that means migrations missing from git, conflicts with local ones
// (InconsistentMigrationHistory) and a risk of schema-destroying changes nobody reviewed. The
// developer writes migrations locally and commits them; we apply what is ready (migrate).
// Instead of generating them we run `makemigrations --check`, which creates no files and only
// warns that the models drifted away from the migrations.
func (d *Deployer) djangoTasks(ctx context.Context) *DeployError {
	d.dep.log("django", KindStep, "Django: применяю миграции и собираю статику…")
	inner := `python manage.py makemigrations --check --dry-run || echo "djaploy: ВНИМАНИЕ — есть изменения моделей без миграций. Сделай makemigrations локально и закоммить (миграции на сервере мы намеренно не генерим)."; ` +
		`python manage.py migrate --noinput && python manage.py collectstatic --noinput`
	cmd := fmt.Sprintf(`cd %q && docker compose %s exec -T %s sh -c %s 2>&1`,
		d.dir, d.composeFiles(), sq(d.dep.AppService), sq(inner))
	if err := d.run(ctx, "django", cmd); err != nil {
		return derr("django_tasks_failed",
			"Проект развёрнут и работает, но авто-миграции или сбор статики не прошли.",
			"Проверь, что в сервисе «"+d.dep.AppService+"» есть manage.py и в настройках задан STATIC_ROOT. Вручную: docker compose exec "+d.dep.AppService+" python manage.py migrate")
	}
	d.dep.log("django", KindOK, "Миграции применены, статика собрана")
	return nil
}

// provisionVPN (soft) brings up AmneziaWG (WireGuard with obfuscation) and writes a client
// config into .djaploy/wg-client.conf. The user imports it into AmneziaVPN or Happ. Never fails
// the deploy.
func (d *Deployer) provisionVPN(ctx context.Context) *DeployError {
	d.dep.log("vpn", KindStep, "Поднимаю AmneziaWG (приватный VPN до сервера) и готовлю конфиг…")
	cfgDir := d.dir + "/.djaploy"
	// If the user closed off some paths, the client has to reach the server through the tunnel so
	// that Caddy sees it as trusted (10.8.0.x). That needs a full tunnel.
	allowedIPs := "10.8.0.0/24"
	if len(d.dep.ServerState.VPNPaths) > 0 {
		allowedIPs = "0.0.0.0/0"
	}
	// AmneziaWG obfuscation parameters, generated once because they must match on the server and
	// on the client. Jc/Jmin/Jmax are junk packets, S1/S2 junk sizes, H1..H4 randomize headers.
	obf := `JUNK=$(shuf -i 5-2147483640 -n 4)
H1=$(echo "$JUNK" | sed -n 1p); H2=$(echo "$JUNK" | sed -n 2p)
H3=$(echo "$JUNK" | sed -n 3p); H4=$(echo "$JUNK" | sed -n 4p)
OBF="Jc = 4\nJmin = 40\nJmax = 70\nS1 = 50\nS2 = 100\nH1 = $H1\nH2 = $H2\nH3 = $H3\nH4 = $H4"`
	script := `set -e
export DEBIAN_FRONTEND=noninteractive
WGDIR=/etc/amnezia/amneziawg
# REUSE (multi-site): there is ONE VPN per server. If awg0 is already up because another site
# brought it up, we do NOT touch the tunnel (that would break the neighbour's VPN) and only
# regenerate THIS project's client config from the existing keys, port and obfuscation, then exit.
if command -v awg >/dev/null 2>&1 && awg show awg0 >/dev/null 2>&1 && [ -f "$WGDIR/client_private.key" ] && [ -f "$WGDIR/awg0.conf" ]; then
  mkdir -p ` + sq(cfgDir) + `
  CPRIV=$(cat "$WGDIR/client_private.key")
  SPUB=$(cat "$WGDIR/server_public.key")
  PORT=$(awk -F'=' '/ListenPort/{gsub(/[^0-9]/,"",$2);print $2}' "$WGDIR/awg0.conf")
  ENDPOINT=$(curl -s --max-time 5 https://api.ipify.org || echo ` + sq(d.dep.ServerIP) + `)
  OBF=$(awk '/^(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4) *=/' "$WGDIR/awg0.conf")
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n%s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = ` + allowedIPs + `\nPersistentKeepalive = 25\n' "$CPRIV" "$OBF" "$SPUB" "$ENDPOINT" "$PORT" > ` + sq(cfgDir+"/wg-client.conf") + `
  echo "VPN_REUSED (порт $PORT)"
  exit 0
fi
# AmneziaWG is WireGuard plus obfuscation (it gets through DPI blocking). Installed from the Amnezia PPA.
apt-get install -y -o Dpkg::Options::=--force-confnew software-properties-common curl iproute2 >/dev/null 2>&1 || true
# kernel headers: AmneziaWG installs as a DKMS module and is built against the running kernel
apt-get install -y "linux-headers-$(uname -r)" >/dev/null 2>&1 || apt-get install -y linux-headers-generic >/dev/null 2>&1 || true
add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
# on fresh or unusual Ubuntu the PPA may have no packages for our release (404), so we normalize
# the codename to the noble LTS. AmneziaWG installs as a DKMS module (built against the running
# kernel), so the noble package fits and apt is not poisoned by a broken repository.
for f in /etc/apt/sources.list.d/*amnezia*; do
  [ -f "$f" ] && sed -ri 's#(/ppa/ubuntu) +[a-z][a-z0-9]+ #\1 noble #; s/^(Suites:).*/\1 noble/' "$f" || true
done
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y amneziawg amneziawg-tools >/dev/null 2>&1 || { rm -f /etc/apt/sources.list.d/*amnezia* >/dev/null 2>&1; apt-get update -y >/dev/null 2>&1 || true; echo "AWG_INSTALL_FAILED"; exit 7; }
WGDIR=/etc/amnezia/amneziawg
mkdir -p "$WGDIR" /etc/amnezia/clients ` + sq(cfgDir) + `
cd "$WGDIR"
umask 077
[ -f server_private.key ] || awg genkey | tee server_private.key | awg pubkey > server_public.key
[ -f client_private.key ] || awg genkey | tee client_private.key | awg pubkey > client_public.key
SPRIV=$(cat server_private.key); SPUB=$(cat server_public.key)
CPRIV=$(cat client_private.key); CPUB=$(cat client_public.key)
ENDPOINT=$(curl -s --max-time 5 https://api.ipify.org || echo ` + sq(d.dep.ServerIP) + `)
EXTIF=$(ip route show default | awk '/default/ {print $5; exit}')
[ -n "$EXTIF" ] || EXTIF=eth0
` + obf + `
# first take down OUR old tunnel (it may be left over from a previous deploy or from autostart)
# to free our own port before picking one.
systemctl stop awg-quick@awg0 >/dev/null 2>&1 || true
awg-quick down awg0 >/dev/null 2>&1 || true
ip link delete awg0 >/dev/null 2>&1 || true
sleep 1
# pick a free UDP port automatically (51820..51830) so we can live next to someone else's VPN
# instead of failing with "Address already in use".
PORT=""
for p in $(seq 51820 51830); do
  ss -uln 2>/dev/null | grep -qE ":$p[[:space:]]" || { PORT=$p; break; }
done
[ -n "$PORT" ] || PORT=51820
printf '[Interface]\nAddress = 10.8.0.1/24\nListenPort = %s\nPrivateKey = %s\n%b\nPostUp = iptables -I FORWARD -i awg0 -j ACCEPT; iptables -I FORWARD -o awg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\nPostDown = iptables -D FORWARD -i awg0 -j ACCEPT; iptables -D FORWARD -o awg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.8.0.2/32\n' "$PORT" "$SPRIV" "$OBF" "$EXTIF" "$EXTIF" "$CPUB" > "$WGDIR/awg0.conf"
chmod 600 "$WGDIR/awg0.conf"
printf '[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n%b\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = ` + allowedIPs + `\nPersistentKeepalive = 25\n' "$CPRIV" "$OBF" "$SPUB" "$ENDPOINT" "$PORT" > ` + sq(cfgDir+"/wg-client.conf") + `
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-djaploy-wg.conf
command -v ufw >/dev/null 2>&1 && ufw allow "$PORT"/udp >/dev/null 2>&1 || true
iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT
systemctl enable awg-quick@awg0 >/dev/null 2>&1 || true
awg-quick up awg0
echo "VPN_PORT=$PORT"
awg show awg0 >/dev/null 2>&1 && echo "VPN_READY (порт $PORT)" || { echo "awg0 не поднялся"; exit 1; }`
	if err := d.run(ctx, "vpn", script); err != nil {
		return derr("vpn_failed",
			"Проект работает, но VPN (AmneziaWG) поднять не вышло.",
			"Чаще всего: UDP-порт VPN (51820+) закрыт в облачном фаерволе. Порт указан в скачанном конфиге (строка Endpoint) и в логе выше — открой его в фаерволе и повтори деплой.")
	}
	d.dep.markState(func(s *ServerState) { s.VPN = true })
	d.dep.log("vpn", KindOK, "AmneziaWG готов — скачай конфиг на странице деплоя и импортируй в приложение AmneziaVPN")
	if paths := d.dep.ServerState.VPNPaths; len(paths) > 0 {
		d.dep.log("vpn", KindOut, "Закрыты только под VPN: "+strings.Join(paths, ", ")+" — снаружи отдаём 404")
		d.dep.log("vpn", KindOut, "Подключил VPN → эти разделы открываются; отключил → снова закрыты")
	}
	return nil
}

// handoverNonRoot (soft) creates a deploy user (in the docker group), installs our key for it,
// hands over ownership of the project and switches redeploy and CD to that user. On any error we
// stay on root (the deploy already works and the root key is in place). Never fails the deploy.
func (d *Deployer) handoverNonRoot(ctx context.Context) *DeployError {
	user := d.j.deployUserName
	if user == "" {
		user = "deploy"
	}
	d.dep.log("nonroot", KindStep, "Создаю пользователя «"+user+"» и передаю ему проект (уходим от root)…")
	priv, authLine, err := genSSHKey()
	if err != nil {
		return derr("nonroot_failed", "Не удалось сгенерировать ключ для пользователя deploy — остаёмся под root.",
			"Проект работает. Редеплой идёт под root по уже установленному ключу.")
	}
	// if the user gave us their own public key we add it too, so `ssh deploy@IP` works directly
	userKeyLine := ""
	if k := strings.TrimSpace(d.j.userPubKey); strings.HasPrefix(k, "ssh-") || strings.HasPrefix(k, "ecdsa-") {
		userKeyLine = "echo " + sq(k) + " >> /home/" + user + "/.ssh/authorized_keys\n"
	}
	script := `set -e
id -u ` + user + ` >/dev/null 2>&1 || useradd -m -s /bin/bash ` + user + `
getent group docker >/dev/null 2>&1 && usermod -aG docker ` + user + ` || true
mkdir -p /home/` + user + `/.ssh && chmod 700 /home/` + user + `/.ssh
touch /home/` + user + `/.ssh/authorized_keys
grep -qF ` + sq(authLine) + ` /home/` + user + `/.ssh/authorized_keys || echo ` + sq(authLine) + ` >> /home/` + user + `/.ssh/authorized_keys
` + userKeyLine + `chmod 600 /home/` + user + `/.ssh/authorized_keys
chown -R ` + user + `:` + user + ` /home/` + user + `/.ssh
chown -R ` + user + `:` + user + ` ` + sq(d.dir) + `
` + "chown -R " + user + `:` + user + ` /opt/djaploy/_gateway 2>/dev/null || true
echo "deploy ready"`
	if err := d.run(ctx, "nonroot", script); err != nil {
		return derr("nonroot_failed",
			"Не удалось создать отдельного пользователя — оставляю деплой под root.",
			"Проект работает. Можно повторить позже.")
	}
	enc, err := encrypt(d.encKey, priv)
	if err != nil {
		return derr("nonroot_failed", "Ключ deploy не сохранён — остаёмся под root.", "Проект работает.")
	}
	d.dep.mu.Lock()
	d.dep.sshKeyEnc = enc
	d.dep.SSHUser = user
	d.dep.mu.Unlock()
	if d.repo != nil {
		c, cc := context.WithTimeout(context.Background(), 5*time.Second)
		_ = d.repo.SaveSSHKey(c, d.dep.ID, enc)
		cc()
	}
	d.dep.markState(func(s *ServerState) { s.DeployUser = user })
	d.dep.log("nonroot", KindOK, "Создан пользователь «"+user+"» — повторные деплои и CD идут под ним, не под root")
	d.dep.log("nonroot", KindOut, "Как зайти под него: `ssh root@"+d.dep.ServerIP+"` затем `su - "+user+"`")
	if userKeyLine != "" {
		d.dep.log("nonroot", KindOut, "Или напрямую своим ключом: `ssh "+user+"@"+d.dep.ServerIP+"`")
	} else {
		d.dep.log("nonroot", KindOut, "Чтобы заходить напрямую `ssh "+user+"@IP` — добавь свой публичный ключ при следующем деплое (поле в форме)")
	}
	d.dep.log("nonroot", KindOut, "Root-доступ у тебя остаётся прежним — мы его не трогали")
	return nil
}

// STEP 6: HTTPS health check.
func (d *Deployer) health(ctx context.Context) *DeployError {
	d.dep.log("health", KindStep, "Жду ответа по HTTPS (Caddy выпускает SSL)…")
	ip := d.dep.ServerIP
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	// We hit the server IP DIRECTLY, bypassing our own container's DNS (it sometimes flaps), while
	// SNI stays set to the domain, so Caddy serves the right certificate.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return dialer.DialContext(c, network, net.JoinHostPort(ip, port))
		},
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	url := "https://" + d.dep.Domain + "/"
	last := "нет ответа"
	tlsIssue := false
	for i := 0; i < 18; i++ { // roughly up to 2 minutes
		select {
		case <-ctx.Done():
			return derr("health_failed",
				"Контейнеры запущены, но https://"+d.dep.Domain+" так и не ответил (последнее: "+last+").",
				healthHint(d.dep, tlsIssue))
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			code := resp.StatusCode
			resp.Body.Close()
			if code < 500 {
				d.dep.log("health", KindOK, fmt.Sprintf("Сайт ответил %d — живой.", code))
				return nil
			}
			last = fmt.Sprintf("HTTP %d", code)
		} else {
			last = trim(err.Error())
			if strings.Contains(last, "tls") || strings.Contains(last, "certificate") {
				tlsIssue = true
				// Peek into Caddy's logs: on a Let's Encrypt rate limit there is no point in waiting,
				// so we give the exact hint right away instead of a wrong one about ports.
				if (i == 2 || i == 5) && d.caddyRateLimited(ctx) {
					return derr("le_rate_limit",
						"Let's Encrypt временно не выдаёт сертификат для "+d.dep.Domain+" — превышен недельный лимит.",
						leRateLimitHint(d.dep))
				}
			}
		}
		d.dep.log("health", KindOut, "ещё не готов ("+last+"), жду…")
		time.Sleep(7 * time.Second)
	}
	return derr("health_failed",
		"Контейнеры запущены, но https://"+d.dep.Domain+" не отвечает (последнее: "+last+").",
		healthHint(d.dep, tlsIssue))
}

func healthHint(d *Deployment, tlsIssue bool) string {
	if tlsIssue {
		return "Caddy запустился, но не смог выпустить SSL-сертификат (tls: internal error). " +
			"Почти всегда причина — закрыты порты: открой во ФАЕРВОЛЕ ОБЛАКА входящие TCP 80 и 443 " +
			"(Let's Encrypt проверяет домен по порту 80). Ещё проверь, что A-запись " + d.Domain +
			" указывает на " + d.ServerIP + ". После — нажми «Обновить»."
	}
	return "Проверь: 1) в фаерволе ОБЛАКА открыты входящие TCP 80 и 443; 2) сервис в compose называется «" +
		d.AppService + "» и слушает " + itoa(d.AppPort) + "; 3) приложение реально стартовало (логи приложения на странице). " +
		"Иногда помогает подождать минуту и нажать «Обновить»."
}

// isNetworkErr tells whether a build failure looks like the SERVER's network (Debian
// repositories or registries unreachable) rather than a code error. Common on servers in Russia.
func isNetworkErr(out string) bool {
	o := strings.ToLower(out)
	for _, m := range []string{
		"temporary failure resolving",
		"could not resolve host",
		"unable to connect",
		"failed to fetch",
		"unable to locate package", // fallout from a failed apt-get update
		"connection timed out",
		"i/o timeout",
		"tls handshake timeout",
		"timeout exceeded while awaiting headers",
		"network is unreachable",
		"no route to host",
	} {
		if strings.Contains(o, m) {
			return true
		}
	}
	return false
}

func netErrHint() string {
	return "Сервер не смог скачать пакеты/образы из интернета — это ограничение СЕТИ сервера " +
		"(частое у серверов в РФ: режется доступ к репозиториям Debian и реестрам), а не баг твоего проекта. " +
		"Что делать: повтори деплой (бывает, пролезает со 2–3 раза), либо используй сервер с нормальным доступом в интернет."
}

// caddyRateLimited looks into Caddy's logs to see whether we hit the Let's Encrypt limit.
func (d *Deployer) caddyRateLimited(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Caddy now lives in the shared gateway, so we read its logs (the LE limit is per server)
	cmd := "cd " + gatewayDir + " && docker compose logs caddy --tail 200 2>&1 | grep -iE 'ratelimited|too many certificates' | head -1"
	found := false
	_ = d.ssh.Run(cctx, d.priv(cmd), func(line string) {
		if strings.TrimSpace(line) != "" {
			found = true
		}
	})
	return found
}

func leRateLimitHint(d *Deployment) string {
	return "Let's Encrypt разрешает максимум 5 сертификатов в неделю на домен — для " + d.Domain +
		" лимит исчерпан (обычно из-за частых пере-деплоев или удалений одного и того же домена). " +
		"Варианты: подождать сброса лимита (до недели) или развернуть на другом поддомене. " +
		"Контейнеры и сайт работают — это только про выпуск нового SSL."
}

// checkDNS resolves the domain and compares it with the server IP (no SSH involved).
func checkDNS(domain, ip string) *DeployError {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return derr("dns_unresolved",
			"Домен "+domain+" не резолвится.",
			"Добавь A-запись "+domain+" → "+ip+" у DNS-провайдера и подожди обновления (TTL).")
	}
	if slices.Contains(ips, ip) {
		return nil
	}
	return derr("dns_mismatch",
		"Домен "+domain+" указывает не на "+ip+" (сейчас на: "+strings.Join(ips, ", ")+").",
		"Поменяй A-запись "+domain+" → "+ip+" и подожди пару минут. Без этого Caddy не сможет выпустить SSL.")
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 140 {
		return s[:140] + "…"
	}
	return s
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// sq safely wraps a value in single quotes for bash, in case the superuser login or password
// contains special characters.
func sq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
