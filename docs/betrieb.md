# Betrieb

## Installation

```sh
git clone https://github.com/inv1sible/way.git && cd way
cp .env.example .env
docker compose up -d --build
```

Zufallswerte für Secrets: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.

## Konfiguration (`.env`)

| Variable | Bedeutung |
|---|---|
| `DJANGO_SECRET_KEY` | Pflicht, zufällig |
| `DJANGO_ALLOWED_HOSTS` | Hostnamen/IPs, unter denen die UI erreichbar ist |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Öffentliche HTTPS-Adresse(n) hinter dem Reverse Proxy, z. B. `https://way.example.org` |
| `DJANGO_SECURE_COOKIES` | `1` = Cookies nur über HTTPS (Standard); `0` nur für Tests über http |
| `DJANGO_SUPERUSER_*` | Erster Benutzer, wird beim Start angelegt, falls er fehlt |
| `APP_BIND`, `APP_PORT` | Interface und Port der UI auf dem Host |
| `POSTGRES_*` | Datenbank; `POSTGRES_PASSWORD` setzen |
| `SEARXNG_SECRET` | Pflicht für die Websuche |
| `TOOLS_TOKEN` | Pflicht; Zugangsschutz des `tools`-Containers |
| `OLLAMA_URL`, `OLLAMA_MODEL` | Ollama-Server und Modell (getestet: `qwen3:8b`) |
| `DEFAULT_REGION` | Land für Rufnummern ohne Ländervorwahl (`DE`) |
| `TRUSTED_PROXIES` | Reverse Proxy(s), deren `X-Forwarded-For` vertraut wird (für die Login-Sperre) |
| `EMAIL_*`, `DEFAULT_FROM_EMAIL` | SMTP für Einladungen und "Passwort vergessen"; ohne `EMAIL_HOST` landen Mails im Log |
| API-Keys | siehe [quellen.md](quellen.md) |

Nach Änderungen an `.env`: `docker compose up -d` (erstellt die Container neu; `restart` liest `.env` nicht neu).

## Reverse Proxy

Die App erwartet HTTPS über einen Reverse Proxy (z. B. Nginx Proxy Manager):

- `DJANGO_CSRF_TRUSTED_ORIGINS` auf die öffentliche Adresse setzen, `TRUSTED_PROXIES` auf die Adresse des Proxys.
- **Kein Caching für JavaScript** im Proxy: Der Service Worker liegt deshalb unter `/service-worker` (ohne `.js`),
  aber auch `app.js` sollte nicht zwischengespeichert werden (in NPM: "Cache Assets" aus).
- Greifen Geräte im LAN über die öffentliche Domain zu, sehen sie bei Hairpin-NAT alle wie der Router aus und
  teilen sich die Login-Sperre. Abhilfe: lokaler DNS-Eintrag der Domain auf den Proxy.

## Ollama

Ein Bericht braucht je nach Grafikspeicher 1–3 Minuten. Passt das Modell nicht ganz in den Grafikspeicher, läuft
ein Teil auf der CPU und es wird deutlich langsamer. Ist Ollama nicht erreichbar, schlägt nur der Bericht fehl;
die Rohdaten bleiben gespeichert und "Erneut analysieren" holt ihn nach.

## Updates

```sh
git pull
docker compose up -d --build
```

Migrationen laufen beim Start des `web`-Containers automatisch. Der Neustart von `web` führt zu wenigen Sekunden
Ausfall (502 am Proxy). Der Worker hat `stop_grace_period: 5m`, damit laufende Analysen zu Ende laufen; vom
Neustart unterbrochene Analysen werden beim nächsten Start als fehlgeschlagen markiert.

## Neue Migrationen erzeugen

```sh
docker compose run --rm -u "$(id -u)" -v "$PWD/web:/app" web python manage.py makemigrations
```

## Backups

Zu sichern sind die Datenbank und `.env`:

```sh
docker compose exec -T db pg_dump -U osint osint | gzip > way-$(date +%F).sql.gz
```
