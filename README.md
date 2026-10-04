# OSINT-Agent

Rufnummer oder IP-Adresse in die Web-UI eingeben und einen KI-Bericht mit Risikoeinschätzung erhalten.
Die Daten werden ohne KI aus freien Quellen gesammelt, ein lokales LLM über Ollama bewertet sie.

## Dienste (docker compose)

| Dienst | Aufgabe |
|---|---|
| `web` | Django-Web-UI (Gunicorn, Login, Verlauf, Admin unter `/admin/`) |
| `worker` | Celery-Worker: fragt Quellen ab, lässt Bericht schreiben |
| `db` | PostgreSQL |
| `redis` | Message-Broker für Celery |
| `searxng` | Selbst gehostete Metasuche für Rufnummern |

Ollama läuft extern (`OLLAMA_URL`, Standard `http://192.168.1.139:11434`, Modell `qwen3:8b`).

## Quellen

- **Rufnummer:** libphonenumber (Land, Ortsnetz, Typ, ursprünglicher Netzbetreiber), Nummernbereiche der
  Bundesnetzagentur, Ping-Anruf-Heuristik, Websuche über SearXNG (nur Treffer, die die Nummer enthalten).
- **IP-Adresse:** Reverse DNS, RDAP (Netzinhaber, Abuse-Kontakt), ip-api.com (Geo/ASN, Hosting/Proxy),
  Shodan InternetDB, GreyNoise Community, Tor-Exit-Liste, Spamhaus ZEN, optional AbuseIPDB (`ABUSEIPDB_KEY`).

## Start

```sh
cp .env.example .env    # Secrets und Passwörter setzen
docker compose up -d --build
```

Die Web-UI läuft unter `http://<host>:${APP_PORT}`. Der Benutzer aus `DJANGO_SUPERUSER_*` wird beim ersten
Start angelegt; weitere Benutzer unter `/admin/`.

## Tests

```sh
docker compose run --rm web python manage.py test lookups
```

## Nach Codeänderungen am Modell

```sh
docker compose run --rm -u "$(id -u)" -v "$PWD/web:/app" web python manage.py makemigrations
```
