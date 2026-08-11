package deploy

import (
	"context"
	"time"
)

// runRedeploy is the short update cycle: connect by KEY (no password), pull fresh code and
// rebuild. The .env file and the database volumes are NOT touched, so the data stays in place.
func runRedeploy(ctx context.Context, repo *Repo, dep *Deployment, keyPEM, token string) {
	dep.setStatus(StatusRunning)
	persist(repo, dep, false)

	dep.setStep("connect", "running")
	dep.log("connect", KindStep, "Подключаюсь по ключу: "+dep.SSHUser+"@"+dep.ServerIP)
	sshc, hkErr, err := dialKeyPinned(ctx, repo, dep.UserID, dep.ServerIP, dep.SSHUser, keyPEM)
	if hkErr != nil {
		failStep(repo, dep, "connect", hkErr)
		return
	}
	if err != nil {
		failStep(repo, dep, "connect", derr("ssh_failed",
			"Не удалось подключиться по сохранённому ключу.",
			"Возможно, ключ удалили с сервера. Запусти обычный деплой заново — он переустановит доступ."))
		return
	}
	defer sshc.Close()
	dep.setStep("connect", "done")
	dep.log("connect", KindOK, "Подключился")

	d := &Deployer{ssh: sshc, dep: dep, repo: repo, token: token, dir: "/opt/djaploy/" + sanitizeName(dep.Repo)}

	type stepDef struct {
		key     string
		timeout time.Duration
		soft    bool
		fn      func(context.Context) *DeployError
	}
	// caddy and health are web only (workers have no domain and no gateway). setupGateway
	// regenerates the snippet in the shared Caddy, which picks up VPN, Grafana and any fixes.
	steps := []stepDef{{"pull", 4 * time.Minute, false, d.pull}}
	if !dep.IsWorker() {
		steps = append(steps, stepDef{"caddy", 5 * time.Minute, false, d.setupGateway})
	}
	steps = append(steps, stepDef{"up", 18 * time.Minute, false, d.composeUp})
	// Django: migrate and collectstatic run on redeploy too, since new code may bring new migrations.
	if frameworkOrDefault(dep.ServerState.Framework) == frameworkDjango {
		steps = append(steps, stepDef{"django", 5 * time.Minute, true, d.djangoTasks})
	}
	if !dep.IsWorker() {
		steps = append(steps, stepDef{"health", 3 * time.Minute, false, d.health})
	}
	for _, st := range steps {
		dep.setStep(st.key, "running")
		persist(repo, dep, false)
		sctx, cancel := context.WithTimeout(ctx, st.timeout)
		de := st.fn(sctx)
		cancel()
		if de != nil {
			// a soft step (django) never fails the redeploy, the site is already updated, so we warn
			if st.soft {
				dep.setStep(st.key, "done")
				dep.log(st.key, KindError, de.Message)
				if de.Hint != "" {
					dep.log(st.key, KindError, "→ "+de.Hint)
				}
				persist(repo, dep, false)
				continue
			}
			failStep(repo, dep, st.key, de)
			return
		}
		dep.setStep(st.key, "done")
		persist(repo, dep, false)
	}

	d.recordRelease() // remember the new commit in case of a later rollback
	dep.setURL("https://" + dep.Domain)
	dep.setStatus(StatusSuccess)
	dep.log("", KindOK, "Обновлено ✓  https://"+dep.Domain)
	persist(repo, dep, true)
	dep.finish()
}

// runRollback goes back to a previous version: connect by key, check out the target commit and
// rebuild. The .env file and the data volumes are left alone. On success we pop the version we
// rolled back from, so the target becomes the current top of the history.
func runRollback(ctx context.Context, repo *Repo, dep *Deployment, keyPEM, token, targetSHA string) {
	dep.setStatus(StatusRunning)
	persist(repo, dep, false)

	dep.setStep("connect", "running")
	dep.log("connect", KindStep, "Подключаюсь по ключу: "+dep.SSHUser+"@"+dep.ServerIP)
	sshc, hkErr, err := dialKeyPinned(ctx, repo, dep.UserID, dep.ServerIP, dep.SSHUser, keyPEM)
	if hkErr != nil {
		failStep(repo, dep, "connect", hkErr)
		return
	}
	if err != nil {
		failStep(repo, dep, "connect", derr("ssh_failed",
			"Не удалось подключиться по сохранённому ключу.",
			"Возможно, ключ удалили с сервера. Запусти обычный деплой заново."))
		return
	}
	defer sshc.Close()
	dep.setStep("connect", "done")
	dep.log("connect", KindOK, "Подключился")

	d := &Deployer{ssh: sshc, dep: dep, repo: repo, token: token,
		dir: "/opt/djaploy/" + sanitizeName(dep.Repo), rollbackSHA: targetSHA}

	type stepDef struct {
		key     string
		timeout time.Duration
		fn      func(context.Context) *DeployError
	}
	steps := []stepDef{{"rollback", 4 * time.Minute, d.rollbackCheckout}}
	if !dep.IsWorker() {
		steps = append(steps, stepDef{"caddy", 5 * time.Minute, d.setupGateway})
	}
	steps = append(steps, stepDef{"up", 18 * time.Minute, d.composeUp})
	if !dep.IsWorker() {
		steps = append(steps, stepDef{"health", 3 * time.Minute, d.health})
	}
	for _, st := range steps {
		dep.setStep(st.key, "running")
		persist(repo, dep, false)
		sctx, cancel := context.WithTimeout(ctx, st.timeout)
		de := st.fn(sctx)
		cancel()
		if de != nil {
			failStep(repo, dep, st.key, de)
			return
		}
		dep.setStep(st.key, "done")
		persist(repo, dep, false)
	}

	// Success: when we stepped back from a working top, that top is removed. When we restored the
	// last working version after a failure (target == top), the stack stays as it is.
	dep.markState(func(s *ServerState) {
		if n := len(s.Releases); n >= 2 && s.Releases[n-1].SHA != targetSHA {
			s.Releases = s.Releases[:n-1]
		}
	})
	if dep.IsWorker() {
		dep.log("", KindOK, "Откат выполнен ✓  контейнеры пересобраны на предыдущей версии")
	} else {
		dep.setURL("https://" + dep.Domain)
		dep.log("", KindOK, "Откат выполнен ✓  https://"+dep.Domain)
	}
	dep.setStatus(StatusSuccess)
	persist(repo, dep, true)
	dep.finish()
}

// rollbackSteps lists the rollback steps for the UI (web has Caddy and health, a worker does not).
func rollbackSteps(worker bool) []StepState {
	steps := []StepState{
		{Key: "connect", Title: "SSH-подключение", Status: "pending"},
		{Key: "rollback", Title: "Откат кода", Status: "pending"},
	}
	if !worker {
		steps = append(steps, StepState{Key: "caddy", Title: "Конфиг Caddy", Status: "pending"})
	}
	steps = append(steps, StepState{Key: "up", Title: "Пересборка и запуск", Status: "pending"})
	if !worker {
		steps = append(steps, StepState{Key: "health", Title: "Проверка", Status: "pending"})
	}
	return steps
}

// pull fetches fresh code without losing the .env or the data: git fetch plus reset --hard,
// which leaves untracked files such as .env and Caddyfile alone.
func (d *Deployer) pull(ctx context.Context) *DeployError {
	d.dep.log("pull", KindStep, "Тяну свежий код (git fetch + reset)…")
	script := "set -e\ncd " + sq(d.dir) + "\n" +
		"git " + gitAuth(d.dep.Provider, d.token) + "fetch --depth 1 origin\n" +
		"git reset --hard origin/HEAD 2>/dev/null || git reset --hard @{u}\n" +
		"echo 'Код обновлён.'"
	if err := d.run(ctx, "pull", script); err != nil {
		return derr("pull_failed",
			"Не удалось обновить код из репозитория.",
			"Проверь, что у сервиса всё ещё есть доступ к репозиторию (GitHub — кнопка «Управление» на дашборде, GitLab — привязка в настройках).")
	}
	return nil
}

// redeploySteps lists the redeploy steps for the UI (server prep is not repeated).
func redeploySteps(withDjango bool) []StepState {
	steps := []StepState{
		{Key: "connect", Title: "SSH-подключение", Status: "pending"},
		{Key: "pull", Title: "Обновление кода", Status: "pending"},
		{Key: "caddy", Title: "Конфиг Caddy", Status: "pending"},
		{Key: "up", Title: "Пересборка и запуск", Status: "pending"},
	}
	if withDjango {
		steps = append(steps, StepState{Key: "django", Title: "Django: миграции и статика", Status: "pending"})
	}
	steps = append(steps, StepState{Key: "health", Title: "Проверка", Status: "pending"})
	return steps
}
