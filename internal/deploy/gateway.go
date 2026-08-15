package deploy

import (
	"context"
	"path/filepath"
)

// --- gateway model: one shared Caddy per server for several sites (see MULTISITE_DESIGN.md).
// These are the building blocks of its lifecycle. They are wired into the main deploy path as a
// SEPARATE phase (tested on a throwaway VPS); for now renderCaddyfile/composeUp work as before.

const gatewayDir = "/opt/djaploy/_gateway"

// ensureGateway creates (idempotently) the shared Caddy stack: the shared network, folders, compose,
// the root Caddyfile, and brings it up. Existing sites are untouched. Safe to call again.
func (d *Deployer) ensureGateway(ctx context.Context) error {
	// the shared network the gateway uses to reach project app and grafana containers by alias
	if err := d.run(ctx, "gateway", d.priv("docker network create "+gwNet+" 2>/dev/null || true")); err != nil {
		return err
	}
	if err := d.run(ctx, "gateway", d.priv("mkdir -p "+gatewayDir+"/sites")); err != nil {
		return err
	}
	if err := d.writeFile(gatewayDir+"/docker-compose.yml", renderGatewayCompose(), "644"); err != nil {
		return err
	}
	if err := d.writeFile(gatewayDir+"/Caddyfile", renderGatewayCaddyfile(), "644"); err != nil {
		return err
	}
	// bring the gateway up (if it already runs, up -d just converges it to the desired state)
	return d.run(ctx, "gateway", d.priv("cd "+gatewayDir+" && docker compose up -d 2>&1"))
}

// writeSiteSnippetFile writes or updates the site config in the gateway (WITHOUT a reload). The reload
// comes after ensureGateway: on a first deploy the file must exist BEFORE Caddy starts (or import is empty).
func (d *Deployer) writeSiteSnippetFile() error {
	name := filepath.Base(d.dir) // имя проекта = папка в /opt/djaploy = алиас/путь статики
	return d.writeFile(gatewayDir+"/sites/"+name+".caddy", renderSiteSnippet(d.dep, name), "644")
}

// reloadGateway rereads the Caddy config with zero downtime (a valid config applies without a restart).
func (d *Deployer) reloadGateway(ctx context.Context) error {
	cmd := "cd " + gatewayDir + " && docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile 2>&1"
	return d.run(ctx, "gateway", d.priv(cmd))
}

// setupGateway is the "caddy" deploy step for a WEB project (gateway model). Idempotent: static folders,
// the overlay (monitoring plus bind volumes), the site snippet, bringing the shared Caddy up. Attaching
// the app to the gateway network happens AFTER composeUp (the app must come up first), in connectGateway.
func (d *Deployer) setupGateway(ctx context.Context) *DeployError {
	d.dep.log("caddy", KindStep, "Настраиваю общий Caddy-шлюз (HTTPS, несколько сайтов на сервер)…")

	// folders for the bind-backed static and media volumes (the device must exist BEFORE up)
	if err := d.run(ctx, "caddy", d.priv("mkdir -p "+sq(d.dir+"/_static")+" "+sq(d.dir+"/_media"))); err != nil {
		return derr("gateway_failed", "Не удалось создать папки статики.", "Проблема доступа/места на сервере.")
	}
	// the project overlay (monitoring plus bind volumes) and the monitoring configs
	if err := d.writeFile(d.dir+"/docker-compose.caddy.yml", renderGatewayOverlay(d.dep, d.dir), "644"); err != nil {
		return derr("gateway_failed", "Не удалось записать docker-compose.caddy.yml.", "Проблема доступа/места на сервере.")
	}
	if d.dep.ServerState.Grafana {
		mon := map[string]string{
			"/monitoring/prometheus.yml":              renderPrometheusYml(),
			"/monitoring/datasources/prometheus.yml":  renderGrafanaDatasource(),
			"/monitoring/dashboards-cfg/provider.yml": renderGrafanaDashboardProvider(),
			"/monitoring/dashboards/overview.json":    renderGrafanaDashboard(),
		}
		for path, content := range mon {
			if err := d.writeFile(d.dir+path, content, "644"); err != nil {
				return derr("gateway_failed", "Не удалось записать конфиг мониторинга ("+path+").", "Проблема доступа/места на сервере.")
			}
		}
	}
	// the site snippet (a file) → the shared Caddy (now with at least one site). The app is attached after up.
	if err := d.writeSiteSnippetFile(); err != nil {
		return derr("gateway_failed", "Не удалось записать конфиг сайта в шлюз.", "Проблема доступа/места на сервере.")
	}
	if err := d.ensureGateway(ctx); err != nil {
		return derr("gateway_failed", "Не удалось поднять общий Caddy-шлюз.",
			"Смотри лог выше — обычно занят порт 80/443 другим процессом или нет доступа к Docker.")
	}
	if err := d.reloadGateway(ctx); err != nil {
		d.dep.log("caddy", KindOut, "(reload Caddy пропущен — конфиг применён при старте шлюза)")
	}
	d.dep.markState(func(s *ServerState) { s.Caddy = true })
	return nil
}

// connectGateway runs AFTER composeUp: it attaches the project's app (and grafana) to the shared gateway
// network under the app-<project> / grafana-<project> aliases so Caddy can reach them, then reloads. Called
// from composeUp for web projects, which covers deploy, redeploy and rollback in one place. docker network
// connect is ADDITIVE, so the app keeps its network to db and redis. || true: on a redeploy it is attached.
func (d *Deployer) connectGateway(ctx context.Context) *DeployError {
	name := filepath.Base(d.dir)
	base := "cd " + sq(d.dir) + " && docker compose -f docker-compose.yml -f docker-compose.caddy.yml "
	// Idempotent: the app-<name> alias must point at EXACTLY the live application container.
	// The problem this fixes: after "unlink, then deploy again" an old container with the same alias
	// could stay on the gateway network, and Caddy would round-robin between the live one and the dead one
	// (the user catches random 502s). So we first take every container of THIS project off the gateway
	// network except the live one, then reconnect the live one and the alias becomes unambiguous.
	sweep := func(svc, alias, idvar string) string {
		return idvar + "=$(" + base + "ps -q " + sq(svc) + " 2>/dev/null | head -1)\n" +
			`[ -n "$` + idvar + `" ] || { echo "контейнер сервиса ` + svc + ` не найден"; exit 1; }` + "\n" +
			// drop the alias from every container of this compose project on the gateway network but the live one
			"for _c in $(docker network inspect " + gwNet + ` -f '{{range $id,$c := .Containers}}{{$id}} {{$c.Name}}{{"\n"}}{{end}}' 2>/dev/null | awk -v a="$` + idvar + `" 'index($1,a)!=1 && $2 ~ /^` + name + `[-_]/ {print $1}'); do` + "\n" +
			"  docker network disconnect -f " + gwNet + ` "$_c" 2>/dev/null || true` + "\n" +
			"done\n" +
			// reconnect the live one: disconnect (in case it was attached in an old state) and connect with the alias
			"docker network disconnect " + gwNet + ` "$` + idvar + `" 2>/dev/null || true` + "\n" +
			"docker network connect --alias " + alias + "-" + name + " " + gwNet + ` "$` + idvar + `"` + "\n"
	}
	script := "set -e\n" + sweep(d.dep.AppService, "app", "AID")
	if d.dep.ServerState.Grafana {
		// grafana is optional, so a missing container must not fail the whole up
		script += "GID=$(" + base + "ps -q grafana 2>/dev/null | head -1)\n" +
			`if [ -n "$GID" ]; then docker network disconnect ` + gwNet + ` "$GID" 2>/dev/null || true; docker network connect --alias grafana-` + name + " " + gwNet + ` "$GID"; fi` + "\n"
	}
	if err := d.run(ctx, "up", d.priv(script)); err != nil {
		return derr("gateway_failed", "Не удалось подключить приложение к шлюзу (общая сеть).",
			"Контейнер приложения должен быть запущен. Сервис «"+d.dep.AppService+"» точно слушает порт "+itoa(d.dep.AppPort)+"?")
	}
	if err := d.reloadGateway(ctx); err != nil {
		d.dep.log("up", KindOut, "(reload шлюза не прошёл — повтори деплой)")
	}
	return nil
}
