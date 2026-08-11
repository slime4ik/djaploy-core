# The shared Caddy gateway

Several web projects can live on one server. This document describes how, and it matches the code
in [`internal/deploy/gateway.go`](../internal/deploy/gateway.go) and
[`internal/deploy/templates.go`](../internal/deploy/templates.go).

## The problem it solves

Ports 80 and 443 exist once per machine. If every project brought its own Caddy, the second deploy
onto that server would fail on a port conflict, and the whole idea of running your side projects on
one cheap VPS would fall apart.

## The layout on your server

```
/opt/djaploy/_gateway/
  docker-compose.yml       one Caddy, ports 80 and 443, on the shared network
  Caddyfile                a single line: import sites/*.caddy
  sites/<project>.caddy    one snippet per site
/opt/djaploy/<project>/    your repository, your compose, plus our overlay
  docker-compose.caddy.yml overlay: monitoring and the static/media volumes
  .env                     yours, plus the domain variables
  _static/ _media/         bind-backed volumes Caddy serves files from
  .djaploy/wg-client.conf  the VPN client config, if you enabled the VPN
```

Rendered by `renderGatewayCompose`, `renderGatewayCaddyfile`, `renderSiteSnippet` and
`renderGatewayOverlay` in `templates.go`.

## How Caddy reaches your app

Over a shared docker network called `djaploy`, not over host ports. After `docker compose up` the
deploy attaches your app container to that network under the alias `app-<project>`, and the site
snippet proxies to `app-<project>:<port>`. Grafana, when enabled, gets `grafana-<project>`.

`docker network connect` is additive: your app keeps its own compose network, so it still talks to
its database and Redis exactly as before. We never edit the networking section of your
`docker-compose.yml`.

The code is `gateway.go` → `connectGateway`. It does one thing that is not obvious: before attaching
the live container it detaches every other container of the same project from the gateway network.
Without that, a container left over from an earlier deploy could still hold the same alias, Caddy
would round-robin between the live one and the dead one, and you would see random 502s.

## Lifecycle

- **First site on a server.** `ensureGateway` creates the network, the folders, the compose file and
  the root Caddyfile, then brings Caddy up. The site snippet is written first, because on the very
  first deploy the file has to exist before Caddy starts or the import matches nothing.
- **Second site.** The gateway is already there. We write one more snippet and reload.
- **Redeploy.** The snippet is regenerated (so changes to protected paths, Grafana or the port are
  picked up) and Caddy reloads. Neighbouring sites keep serving throughout.
- **Deleting one site.** The snippet is removed, Caddy reloads, and only that project's containers
  come down. If it was the last site, the gateway itself is shut down, because a reload on an empty
  config fails and the deleted site would otherwise hang around until a restart. See
  `services.go` → `Delete`.
- **Server reboot.** Everything runs with `restart: always`, so the gateway and the projects come
  back on their own and Caddy rereads `sites/*.caddy`.

## Concurrency

Two deploys onto the same server would both write into `_gateway` and both reload Caddy. Web deploys
are therefore serialized per server IP with a mutex (`services.go` → `lockServer`, `serverLocks`).
Workers and bots take no lock: they have no gateway and no ports, so they deploy in parallel.

## What one snippet looks like

```caddy
your-domain.tld {
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
	route {
		@protected {
			path /admin /admin/ /admin/*
			not remote_ip 10.8.0.0/24
		}
		respond @protected "404 Not Found" 404

		handle_path /static/* {
			root * /srv/your-project/_static
			file_server
		}

		reverse_proxy app-your-project:8000 {
			header_up X-Real-IP {http.request.remote.host}
			lb_try_duration 30s
			lb_try_interval 250ms
		}
	}
}
```

The `route` block is not decoration. Without it Caddy reorders directives and a bare `reverse_proxy`
would grab the request before the 404 rule ever ran, quietly unprotecting the protected paths.
Inside `route` the order is exactly top to bottom.
