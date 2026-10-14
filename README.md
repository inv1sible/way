# Who Are You (WAY)

A self-hosted OSINT tool for investigating email addresses, phone numbers, IP addresses, and hostnames.
WAY collects evidence from registries, DNS, public web search, reputation services, and optional API providers.
A local language model provided through [Ollama](https://ollama.com) produces German and English reports.
Source responses remain available for inspection, with links to public findings and timestamped DNS history.
Analysis data stays on your server except for queries sent to the selected providers and links opened in your browser.

- **Phone numbers:** country, area code, carrier, measures published by the German Federal Network Agency,
  community ratings, and web references through a self-hosted SearXNG instance.
- **Email addresses:** public web searches submit the complete quoted address, retain returned results and engine
  attribution for review, and include directly supported references in reports. Direct browser links offer the same
  full-address search, including Google Verbatim. Optional Have I Been Pwned provides breach metadata.
- **IP addresses and hostnames:** network owner, location, and ASN context from IPinfo.io, DNS, reputation data
  from VirusTotal, AbuseIPDB, CrowdSec, GreyNoise, AlienVault OTX, abuse.ch, and Spamhaus, plus bounded passive
  internet-scan data from Shodan, Censys, and optionally Netlas.
  TLS certificates, web headers, and port scans are optionally available for registered owned systems.
- **History:** repeated analyses of the same query are grouped and compared for changed addresses, ports,
  reputation, and risk. A historical date can optionally add BGP and passive-DNS history. Available historical DNS
  observations appear in the detail page and PDF with readable dates, times, and source attribution.
- **Interface:** German and English, installable as a mobile PWA with a share target, live progress, PDF export,
  notes, and invitation-based multi-user support.

Public web search depends on the upstream engines available to the server. Quoted queries are forwarded intact,
but blocks, CAPTCHAs, parser failures, and irrelevant provider responses can reduce coverage. The raw data records
the requested query and SearXNG's echoed query; an empty result is not proof that no public reference exists.
The optional Google Custom Search JSON API connector supports existing customers only and is scheduled to end on
January 1, 2027; see [Data sources](docs/quellen.md#email-addresses).

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

WAY supports public-source research into email addresses, phone numbers, IP addresses, and hostnames.
Active requests such as TLS, web metadata, and port scans against third-party systems may be unlawful in some
jurisdictions. Port scanning is therefore restricted to registered owned systems. The terms of service of every
data provider continue to apply.
