package deploy

import (
	"fmt"
	"strings"
)

// --- Gateway model: one shared Caddy per server serving SEVERAL sites (see docs/multisite.md).
// Everything below renders the files that gateway.go writes onto the server.

// gwSecHeaders holds the security headers for a site block (one tab of indentation).
const gwSecHeaders = `	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
`

// gwPathGuard protects paths (VPNPaths) so only trusted IPs reach them, inside route{}. It
// returns "" when there is nothing to protect.
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
	// respond with a BODY (not an empty one) makes Caddy set Content-Type text/plain, so the
	// browser SHOWS the 404 instead of downloading it (an empty response plus our nosniff header
	// turns the page into a file download).
	return fmt.Sprintf(`
		@protected {
			path %s
			not remote_ip %s
		}
		respond @protected "404 Not Found" 404
`, strings.Join(matchers, " "), strings.Join(trusted, " "))
}

// renderGatewayCompose renders the compose file of the shared Caddy: it holds 80/443, reads
// sites/*.caddy and proxies to each project's containers.
// gwNet is the shared docker network the gateway uses to reach every project's app and grafana by
// alias (app-<project> / grafana-<project>). No host ports, which is reliable with any
// userland-proxy setting.
const gwNet = "djaploy"

func renderGatewayCompose() string {
	// Caddy holds 80/443 and proxies to project apps OVER THE SHARED NETWORK (alias app-<project>)
	// rather than over host ports, which is more reliable (loopback publishing and
	// userland-proxy=false do not get along).
	// /opt/djaploy is mounted read-only as /srv, and Caddy serves project static and media from there.
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

// renderSiteSnippet renders the config of ONE site for the gateway: the domain points at the
// project app over the SHARED NETWORK (alias app-<slug>). The slug is the project name and also
// the /srv/<slug>/_static and /srv/<slug>/_media path used to serve files. Caddy serves static and
// media out of the mounted /srv (which is /opt/djaploy), and each can be enabled on its own (media
// often lives in S3 while static stays on the server). Grafana is reached by alias grafana-<slug>.
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

// renderGatewayOverlay renders the overlay on top of the USER's compose: no Caddy of its own and
// no host ports. App and grafana join the shared gateway network in a separate step (docker
// network connect, by alias). The overlay only adds the optional monitoring stack and the
// bind-backed static and media volumes that Caddy serves from /opt/djaploy/<slug>. When there is
// nothing to add it returns a valid `{}`.
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
		return "{}\n" // empty but valid override: there is nothing to add to the user's compose
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

// --- Monitoring configs, written into <project>/monitoring when Grafana is enabled ---

// prometheus.yml describes what to scrape and how, over the internal compose network.
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
