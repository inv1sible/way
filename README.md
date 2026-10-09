# Who Are You (WAY)

A self-hosted OSINT tool: enter a phone number, IP address, or hostname and receive a report with a risk
assessment. Data is collected without AI from free sources such as registries, DNS, reputation services, and web
search. A local language model provided through [Ollama](https://ollama.com) summarizes the findings. Nothing leaves
your own server except the requests sent to those sources.

- **Phone numbers:** country, area code, carrier, measures published by the German Federal Network Agency,
  community ratings, and web references through a self-hosted SearXNG instance.
- **IP addresses and hostnames:** network owner, location, DNS, reputation data from VirusTotal, AbuseIPDB,
  CrowdSec, GreyNoise, AlienVault OTX, abuse.ch, and Spamhaus, plus internet scan data from Shodan and Censys.
  TLS certificates, web headers, and port scans are optionally available for registered owned systems.
- **History:** repeated analyses of the same query are grouped and compared for changed addresses, ports,
  reputation, and risk. A historical date can optionally add BGP and passive-DNS history.
- **Interface:** German and English, installable as a mobile PWA with a share target, live progress, PDF export,
  notes, and invitation-based multi-user support.

## Quick start

Requirements: Docker with Compose and an accessible Ollama server with a model. WAY has been tested with
`qwen3:8b`.

```sh
cp .env.example .env    # Configure secrets, passwords, and OLLAMA_URL; API keys are optional
docker compose up -d --build
```

The web interface is available at `http://<host>:${APP_PORT}`. The account configured through
`DJANGO_SUPERUSER_*` is created on first startup. Additional users can be invited from **Invitations**.

## Documentation

| Document | Contents |
|---|---|
| [docs/bedienung.md](docs/bedienung.md) | Search, options, history, detail page, notes, and mobile sharing |
| [docs/quellen.md](docs/quellen.md) | Data sources, required API keys, and registration links |
| [docs/betrieb.md](docs/betrieb.md) | Installation, `.env` configuration, reverse proxy, Ollama, updates, and backups |
| [docs/architektur.md](docs/architektur.md) | Services, analysis flow, data model, and live updates |
| [docs/sicherheit.md](docs/sicherheit.md) | Request levels, the `tools` container, owned systems, accounts, and operational security |
| [docs/fritzbox-fingerprint.md](docs/fritzbox-fingerprint.md) | Defensive FRITZ!Box detection, authorization, target binding, and limitations |
| [docs/router-fingerprint.md](docs/router-fingerprint.md) | Ownership-bound, profiled active router enrichment |
| [TODO.md](TODO.md) | Open work and plans |

## Tests

```sh
docker compose run --rm web python manage.py test lookups accounts
docker compose run --rm --no-deps -e TOOLS_TOKEN=x tools python -m unittest -v
```

## Legal notice

WAY is intended for investigating unknown callers and systems you own or are explicitly authorized to test.
Active requests such as TLS, web metadata, and port scans against third-party systems may be unlawful in some
jurisdictions. Port scanning is therefore restricted to registered owned systems. The terms of service of every
data provider continue to apply.
