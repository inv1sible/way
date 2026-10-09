# Architecture

## Services

| Service | Responsibility |
|---|---|
| `web` | Django with Gunicorn: interface, login, `/admin/`, and PDF export |
| `worker` | Celery: queries sources and generates the report |
| `tools` | `whois`, `dig`, `openssl`, `curl`, and `nmap` behind a narrow token API; isolated network and public targets only |
| `db` | PostgreSQL |
| `redis` | Celery message broker |
| `searxng` | Self-hosted metasearch for phone numbers |
| Ollama | External service configured through `OLLAMA_URL`; writes the report |

```text
Browser ──HTTPS──> Reverse proxy ──> web ──> db
                                      │       ▲
                                      ▼       │
                                    redis ──> worker ──> Internet sources
                                              │  ├────> searxng
                                              │  ├────> tools (isolated network) ──> target
                                              │  └────> Ollama
```

## Analysis flow

1. `web` detects the input type in `lookups/detect.py`, creates a `Lookup`, and starts the Celery task after the
   database transaction commits.
2. The worker in `lookups/tasks.py` queries sources concurrently through `lookups/collectors/`, asyncio, and httpx.
   Every result is saved immediately so the detail page can display live progress.
3. Earlier runs of the same query by the same user become the **Previous own analyses** source through
   `lookups/history.py`.
4. Source data is size-limited and sent to Ollama through `lookups/llm.py`. The report contains equivalent German
   and English sections. WAY parses the `Risk: …` line, while deterministic rules such as noteworthy open ports
   can raise the risk level in both language versions.
5. Status progresses through waiting, querying sources, generating the AI report, and complete or failed.

## Data model

- **`Lookup`:** query, type, status, risk, raw source data as a JSON list containing `source`, `ok`, and
  `data`/`error`, bilingual Markdown report, note, analysis options (`as_of`, `active_probe`, `active_ports`,
  `active_timeout`, `port_scan`), and owner.
- **`OwnedTarget`:** addresses, networks, or hostnames and expected ASNs authorized for active checks.
- **`accounts`:** invitations and email confirmation.

Users can see only their own analyses; administrators can see all analyses. Historical comparison always uses
analyses belonging to the same owner.

## Live updates

The detail page is composed of fragments under `templates/lookups/live/`. While an analysis is running,
`static/lookups/live.js` polls `/analyse/<id>/status/`. The server returns only fragments whose hashes have changed
and renders nothing when the revision marker has not changed.

## Report interface

No additional result, warning, or notice cards are rendered alongside the AI report. Technical limitations,
security decisions, and source findings remain inspectable as raw data and are covered by the AI report when they
matter to its assessment. New sources must not bypass this rule by adding separate cards to the detail page or PDF.

## Comparing runs

`history.facts()` extracts measurable attributes from raw data: addresses, reverse DNS, ASN, TLS certificates,
open ports, German Federal Network Agency and Clever Dialer matches, plus reputation values from AbuseIPDB,
VirusTotal, CrowdSec, GreyNoise, OTX, abuse.ch, Spamhaus, Tor, Shodan, and Censys. Attributes are compared only when
both runs contain them. A missing key or failed source is not treated as a change.

## Tests

Tests live in `web/lookups/tests.py`, `web/accounts/tests.py`, and `tools/test_app.py`. Network access is replaced
with test doubles such as `httpx.MockTransport` and `mock.patch`.
