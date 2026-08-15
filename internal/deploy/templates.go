package deploy

import (
	"fmt"
	"strings"
)

// renderCaddyfile builds the Caddy config for the user's service and port.
// reverse_proxy in Caddy v2 proxies WebSockets (ws/wss) TRANSPARENTLY, no separate
// setting needed, so Channels/ASGI on the same port simply work.
func renderCaddyfile(d *Deployment) string {
	var static string
	if d.ServeStatic {
		static = `
	handle_path /static/* {
		root * /srv/static
		file_server
	}
	handle_path /media/* {
		root * /srv/media
		file_server
	}`
	}
	// Path protection: the listed paths answer 404 to everyone except trusted IPs.
	// Trusted = our VPN subnet (when it is up) plus the user's own IPs/subnets (their VPN or office).
	// With no trusted sources we do not add the guard at all (it would close the path for everyone).
	var vpnGuard string
	if len(d.ServerState.VPNPaths) > 0 {
		var trusted []string
		if d.ServerState.VPN {
			trusted = append(trusted, "10.8.0.0/24") // AmneziaWG: клиент в этой подсети
		}
		trusted = append(trusted, d.ServerState.AllowedIPs...)
		if len(trusted) > 0 {
			var matchers []string
			for _, p := range d.ServerState.VPNPaths {
				p = strings.TrimRight(p, "/")
				// three forms: the bare path, with a slash and sub-paths, so the guard catches
				// /admin, /admin/ and /admin/login alike (independent of how the user typed it).
				matchers = append(matchers, p, p+"/", p+"/*")
			}
			vpnGuard = fmt.Sprintf(`
	@protected {
		path %s
		not remote_ip %s
	}
	respond @protected 404
`, strings.Join(matchers, " "), strings.Join(trusted, " "))
		}
	}
	// optional Grafana on /grafana (Grafana knows about the sub-path itself, so we do not strip the prefix)
	var grafana string
	if d.ServerState.Grafana {
		grafana = `
	handle /grafana/* {
		reverse_proxy grafana:3000
	}`
	}
	// route {} is required: otherwise Caddy reorders the directives and a bare reverse_proxy
	// grabs the request before respond/handle. Inside route the order is strict, top to bottom.
	return fmt.Sprintf(`{$DOMAIN} {
	encode zstd gzip
	# базовые security-заголовки (гигиена): форсим HTTPS, запрещаем угадывание типов,
	# защищаем от кликджекинга, не светим referer и версию сервера.
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
	route {
%s%s%s
		# ws/wss проксируется reverse_proxy автоматически.
		# Деплой без простоя: во время пересборки контейнера (старый погас, новый ещё
		# поднимается) Caddy НЕ отдаёт 502, а придерживает запрос и ретраит апстрим до 30с —
		# пользователь видит чуть дольше загрузку вместо ошибки.
		reverse_proxy %s:%d {
			lb_try_duration 30s
			lb_try_interval 250ms
		}
	}
}
`, vpnGuard, grafana, static, d.AppService, d.AppPort)
}

// --- gateway model: one shared Caddy per server for SEVERAL sites (see MULTISITE_DESIGN.md).
// Phase 2: pure render functions, NOT wired into deploy/purge. renderCaddyfile (the old model) is
// untouched, existing deploys work as before. Deduplicating the path guard logic comes later.

// gwSecHeaders is the same set of security headers as in renderCaddyfile (one tab, inside the site block).
const gwSecHeaders = `	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
`

// gwPathGuard is the path protection (VPNPaths) for trusted IPs inside route{}. Empty when there is nothing to guard.
func gwPathGuard(d *Deployment) string {
	if len(d.ServerState.VPNPaths) == 0 {
		return ""
	}
	var trusted []string
	if d.ServerState.VPN {
		trusted = append(trusted, "10.8.0.0/24")
	}
	trusted = append(trusted, d.ServerState.AllowedIPs...)
	if len(trusted) == 0 {
		return ""
	}
	var matchers []string
	for _, p := range d.ServerState.VPNPaths {
		p = strings.TrimRight(p, "/")
		matchers = append(matchers, p, p+"/", p+"/*")
	}
	// respond WITH a body (not an empty one) makes Caddy set Content-Type text/plain, so the browser SHOWS
	// the 404 instead of downloading a file (an empty response plus our nosniff turns it into a download).
	return fmt.Sprintf(`
		@protected {
			path %s
			not remote_ip %s
		}
		respond @protected "404 Not Found" 404
`, strings.Join(matchers, " "), strings.Join(trusted, " "))
}

// renderGatewayCompose builds the compose of the shared Caddy: it holds 80/443, reads sites/*.caddy and
// proxies to the projects' app containers by host port (host.docker.internal through host-gateway).
// gwNet is the shared docker network the gateway uses to reach every project's app/grafana by alias
// (app-<project> / grafana-<project>). No host ports: reliable with any userland-proxy setting.
const gwNet = "djaploy"

func renderGatewayCompose() string {
	// Caddy holds 80/443 and proxies to the projects' apps OVER THE SHARED NETWORK (the app-<project>
	// alias) rather than host ports, which is reliable (loopback publishing and userland-proxy=false clash).
	// /opt/djaploy is mounted read-only as /srv, and Caddy serves the projects' static/media from there.
	return `services:
  caddy:
    image: caddy:2
    restart: always
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    networks:
      - ` + gwNet + `
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./sites:/etc/caddy/sites:ro
      - /opt/djaploy:/srv:ro
      - caddy_data:/data
      - caddy_config:/config
networks:
  ` + gwNet + `:
    external: true
volumes:
  caddy_data:
  caddy_config:
`
}

// renderGatewayCaddyfile renders the gateway root Caddyfile, which imports every site snippet.
func renderGatewayCaddyfile() string {
	return "import sites/*.caddy\n"
}

// renderSiteSnippet is the config of ONE site for the gateway: domain → the project's app OVER THE
// SHARED NETWORK (alias app-<slug>). slug is the project name (and the /srv/<slug>/_static|_media path).
// Caddy serves static and media from the mounted /srv (= /opt/djaploy), and each can be enabled
// separately (media may live in S3 while static stays on the server). Grafana is the grafana-<slug> alias.
func renderSiteSnippet(d *Deployment, slug string) string {
	var sm string
	if d.ServeStatic {
		sm += fmt.Sprintf(`
		handle_path /static/* {
			root * /srv/%s/_static
			file_server
		}`, slug)
	}
	if d.ServeMedia {
		sm += fmt.Sprintf(`
		handle_path /media/* {
			root * /srv/%s/_media
			file_server
		}`, slug)
	}
	var grafana string
	if d.ServerState.Grafana {
		grafana = fmt.Sprintf(`
		handle /grafana/* {
			reverse_proxy grafana-%s:3000
		}`, slug)
	}
	return fmt.Sprintf(`%s {
	encode zstd gzip
%s	route {
%s%s%s
		reverse_proxy app-%s:%d {
			header_up X-Real-IP {http.request.remote.host}
			lb_try_duration 30s
			lb_try_interval 250ms
		}
	}
}
`, d.Domain, gwSecHeaders, gwPathGuard(d), grafana, sm, slug, d.AppPort)
}

// renderGatewayOverlay is the overlay on top of the USER's compose (gateway model): no Caddy of its own
// and no host ports. App/grafana join the shared gateway network in a separate step (docker network
// connect, by alias). The overlay only adds the monitoring stack (optional) and bind-backed static/media
// volumes (Caddy serves them from /opt/djaploy/<slug>). With nothing to add it returns a valid `{}`.
func renderGatewayOverlay(d *Deployment, projectDir string) string {
	var svc strings.Builder
	if d.ServerState.Grafana {
		svc.WriteString(`  grafana:
    image: grafana/grafana:latest
    restart: always
    environment:
      GF_SERVER_ROOT_URL: https://${DOMAIN}/grafana
      GF_SERVER_SERVE_FROM_SUB_PATH: "true"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/datasources:/etc/grafana/provisioning/datasources:ro
      - ./monitoring/dashboards-cfg:/etc/grafana/provisioning/dashboards:ro
      - ./monitoring/dashboards:/var/lib/grafana/dashboards:ro
    depends_on:
      - prometheus

  prometheus:
    image: prom/prometheus:latest
    restart: always
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=7d'
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus

  node-exporter:
    image: prom/node-exporter:latest
    restart: always
    command:
      - '--path.rootfs=/host'
    pid: host
    volumes:
      - /:/host:ro,rslave
`)
	}

	var vols strings.Builder
	if d.ServeStatic {
		fmt.Fprintf(&vols, "  %s:\n    driver: local\n    driver_opts: { type: none, o: bind, device: %s/_static }\n", d.StaticVolume, projectDir)
	}
	if d.ServeMedia {
		fmt.Fprintf(&vols, "  %s:\n    driver: local\n    driver_opts: { type: none, o: bind, device: %s/_media }\n", d.MediaVolume, projectDir)
	}
	if d.ServerState.Grafana {
		vols.WriteString("  grafana_data:\n  prometheus_data:\n")
	}

	if svc.Len() == 0 && vols.Len() == 0 {
		return "{}\n" // пустой, но валидный override — поверх compose юзера добавлять нечего
	}
	var b strings.Builder
	if svc.Len() > 0 {
		b.WriteString("services:\n")
		b.WriteString(svc.String())
	}
	if vols.Len() > 0 {
		b.WriteString("volumes:\n")
		b.WriteString(vols.String())
	}
	return b.String()
}

// renderOverlay builds our docker-compose.caddy.yml on top of the user's compose.
func renderOverlay(d *Deployment) string {
	var b strings.Builder
	b.WriteString(`services:
  caddy:
    image: caddy:2
    restart: always
    environment:
      DOMAIN: ${DOMAIN}
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
`)
	if d.ServeStatic {
		fmt.Fprintf(&b, "      - %s:/srv/static:ro\n", d.StaticVolume)
		fmt.Fprintf(&b, "      - %s:/srv/media:ro\n", d.MediaVolume)
	}
	b.WriteString(`      - caddy_data:/data
      - caddy_config:/config
    depends_on:
`)
	fmt.Fprintf(&b, "      - %s\n", d.AppService)
	if d.ServerState.Grafana {
		fmt.Fprintf(&b, "      - grafana\n")
	}
	b.WriteString("\n")

	// optional monitoring: Grafana on /grafana plus Prometheus and exporters.
	// The datasource and the dashboard are provisioned automatically, so CPU/RAM/container graphs work out of the box.
	// Exporter ports are NOT published: everything talks over the internal compose network.
	if d.ServerState.Grafana {
		b.WriteString(`  grafana:
    image: grafana/grafana:latest
    restart: always
    environment:
      GF_SERVER_ROOT_URL: https://${DOMAIN}/grafana
      GF_SERVER_SERVE_FROM_SUB_PATH: "true"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/datasources:/etc/grafana/provisioning/datasources:ro
      - ./monitoring/dashboards-cfg:/etc/grafana/provisioning/dashboards:ro
      - ./monitoring/dashboards:/var/lib/grafana/dashboards:ro
    depends_on:
      - prometheus

  prometheus:
    image: prom/prometheus:latest
    restart: always
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=7d'
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus

  node-exporter:
    image: prom/node-exporter:latest
    restart: always
    command:
      - '--path.rootfs=/host'
    pid: host
    volumes:
      - /:/host:ro,rslave

`)
	}

	b.WriteString("volumes:\n")
	if d.ServeStatic {
		fmt.Fprintf(&b, "  %s:\n", d.StaticVolume)
		fmt.Fprintf(&b, "  %s:\n", d.MediaVolume)
	}
	if d.ServerState.Grafana {
		b.WriteString("  grafana_data:\n  prometheus_data:\n")
	}
	b.WriteString("  caddy_data:\n  caddy_config:\n")
	return b.String()
}

// --- monitoring configs (written to <project>/monitoring when Grafana is on) ---

// prometheus.yml describes what to scrape and how (over the internal compose network).
func renderPrometheusYml() string {
	return `global:
  scrape_interval: 30s
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']
  - job_name: node
    static_configs:
      - targets: ['node-exporter:9100']
`
}

// The Grafana datasource uses a fixed uid so the dashboard always binds to it.
func renderGrafanaDatasource() string {
	return `apiVersion: 1
datasources:
  - name: Prometheus
    uid: djaploy-prom
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
`
}

// The dashboard provider makes Grafana pick up json files from /var/lib/grafana/dashboards.
func renderGrafanaDashboardProvider() string {
	return `apiVersion: 1
providers:
  - name: djaploy
    type: file
    disableDeletion: false
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
`
}

// The starter dashboard shows host CPU and RAM plus container resources, with graphs out of the box.
func renderGrafanaDashboard() string {
	return `{
  "title": "djaploy — обзор сервера",
  "uid": "djaploy-overview",
  "schemaVersion": 39,
  "version": 1,
  "refresh": "30s",
  "time": { "from": "now-6h", "to": "now" },
  "panels": [
    {
      "id": 1, "title": "Загрузка CPU, %", "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
      "datasource": { "type": "prometheus", "uid": "djaploy-prom" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100 }, "overrides": [] },
      "targets": [ { "refId": "A", "expr": "100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)", "legendFormat": "CPU" } ]
    },
    {
      "id": 2, "title": "Использование RAM, %", "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 },
      "datasource": { "type": "prometheus", "uid": "djaploy-prom" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100 }, "overrides": [] },
      "targets": [ { "refId": "A", "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100", "legendFormat": "RAM" } ]
    },
    {
      "id": 3, "title": "Использование диска, %", "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 8 },
      "datasource": { "type": "prometheus", "uid": "djaploy-prom" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100 }, "overrides": [] },
      "targets": [ { "refId": "A", "expr": "100 - (sum(node_filesystem_avail_bytes{fstype!~\"tmpfs|overlay|squashfs\"}) / sum(node_filesystem_size_bytes{fstype!~\"tmpfs|overlay|squashfs\"}) * 100)", "legendFormat": "Диск" } ]
    },
    {
      "id": 4, "title": "Средняя нагрузка (1 мин)", "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 8 },
      "datasource": { "type": "prometheus", "uid": "djaploy-prom" },
      "fieldConfig": { "defaults": { "unit": "short", "min": 0 }, "overrides": [] },
      "targets": [ { "refId": "A", "expr": "node_load1", "legendFormat": "load1" } ]
    }
  ]
}
`
}

// renderEnv appends our domain block to the user's .env (our values win because they come last).
// DOMAIN is universal and goes to any stack, while ALLOWED_HOSTS, CSRF, CORS and DEBUG are Django
// specific and are only added for framework=django, so we do not litter the .env of FastAPI, Node
// or Go projects.
func renderEnv(userEnv, domain, framework string) string {
	var block string
	if framework == frameworkDjango {
		block = fmt.Sprintf(`
# --- добавлено djaploy ---
DOMAIN=%s
ALLOWED_HOSTS=%s
CSRF_TRUSTED_ORIGINS=https://%s
CORS_ALLOWED_ORIGINS=https://%s
DEBUG=False
`, domain, domain, domain, domain)
	} else {
		block = fmt.Sprintf("\n# --- добавлено djaploy ---\nDOMAIN=%s\n", domain)
	}
	return strings.TrimRight(userEnv, "\n") + "\n" + block
}
