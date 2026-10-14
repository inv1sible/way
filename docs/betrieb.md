# Operations

## Installation

```sh
git clone https://github.com/inv1sible/way.git && cd way
cp .env.example .env
docker compose up -d --build
```

Generate random secret values with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.

## Configuration (`.env`)

| Variable | Meaning |
|---|---|
| `DJANGO_SECRET_KEY` | Required random application secret |
| `DJANGO_ALLOWED_HOSTS` | Hostnames and IP addresses through which the interface is served |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Public HTTPS origins behind the reverse proxy, for example `https://way.example.org` |
| `DJANGO_SECURE_COOKIES` | `1` restricts cookies to HTTPS and is the default; use `0` only for HTTP testing |
| `DJANGO_SUPERUSER_*` | Initial account, created at startup if missing |
| `APP_BIND`, `APP_PORT` | Host interface and port for the web service |
| `POSTGRES_*` | Database settings; always set `POSTGRES_PASSWORD` |
| `SEARXNG_SECRET` | Required secret for web search |
| `GOOGLE_CSE_API_KEY`, `GOOGLE_CSE_ID` | Optional legacy Google Custom Search JSON API credentials; existing customers only, scheduled discontinuation January 1, 2027. See [Data sources](quellen.md#email-addresses). |
| `TOOLS_TOKEN` | Required authentication token for the `tools` container |
| `OLLAMA_URL`, `OLLAMA_MODEL` | Ollama endpoint and model; tested with `qwen3:8b` |
| `DEFAULT_REGION` | Country used for phone numbers without a country code; default `DE` |
| `TRUSTED_PROXIES` | Reverse proxies whose `X-Forwarded-For` value is trusted for login lockout |
| `EMAIL_*`, `DEFAULT_FROM_EMAIL` | SMTP for invitations and password reset; without `EMAIL_HOST`, mail is written to logs |
| API keys | See [Data sources](quellen.md) |

After changing `.env`, run `docker compose up -d`. A plain restart does not reload environment variables.

## Reverse proxy

WAY expects HTTPS through a reverse proxy such as Nginx Proxy Manager.

- Set `DJANGO_CSRF_TRUSTED_ORIGINS` to the public address and `TRUSTED_PROXIES` to the proxy address.
- Do not cache JavaScript in the proxy. The service worker is therefore served from `/service-worker` without a
  `.js` suffix, but `app.js` must not be cached either. Disable **Cache Assets** in Nginx Proxy Manager.
- When LAN clients access the public domain through hairpin NAT, they may all appear to originate from the router
  and share one login lockout. Add a local DNS record that points the public domain directly to the proxy.

## Ollama

Depending on GPU memory, generating a report takes approximately one to three minutes. If the model does not fit
entirely in GPU memory, partial CPU execution makes it substantially slower. If Ollama is unavailable, only report
generation fails. Raw data remains stored, and **Analyze again** can generate the report later.

## Updates

```sh
git pull
docker compose up -d --build
```

This rebuilds WAY but does not necessarily fetch a newer SearXNG image. To update the search adapters explicitly:

```sh
docker compose pull searxng
docker compose up -d --no-deps --force-recreate searxng
```

The local SearXNG deployment was verified on `2026.10.13+22c64b8d3`. Updating its image does not by itself resolve
upstream blocks or irrelevant Bing responses. The upstream defaults mark Startpage and Mojeek inactive because
of proof-of-work challenges; the removed Presearch engine is not configured. Do not assume that adding
`disabled: false` makes an unsupported or inactive adapter usable.

Email raw data includes `searxng_anfrage`, `searxng_empfangene_suchanfrage`, engine errors, and returned results for
diagnosis. A confirmed echoed query proves reception by SearXNG, not successful execution by every upstream engine.
Changing a query or its language produces a separate cache entry; existing stored reports remain unchanged until rerun.

### Completion convention

After every completed change, rebuild and restart the Compose services with `docker compose up -d --build`, then
verify that the web service is running and responds. Source-level tests alone are not a completed WAY change: the
running containers must use the changed artifact. Do this only for this local WAY deployment; publishing or changing
other environments still requires separate authorization.

Migrations run automatically when the `web` container starts. Restarting `web` causes a few seconds of reverse
proxy errors. The worker has `stop_grace_period: 5m` so running analyses can finish. Runs interrupted by a restart
are marked failed on the next startup.

## Creating migrations

```sh
docker compose run --rm -u "$(id -u)" -v "$PWD/web:/app" web python manage.py makemigrations
```

## Backups

Back up both PostgreSQL and `.env`:

```sh
docker compose exec -T db pg_dump -U osint osint | gzip > way-$(date +%F).sql.gz
```
