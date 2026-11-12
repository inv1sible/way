# Security and operational security

## Request levels

| Level | Contact with target | Sources |
|---|---|---|
| Passive (default) | None; registries, DNS, and third-party services only | RDAP, WHOIS, ASN, DNS records, and reputation services |
| Active-light (administrators, confirmed authorization) | A few ordinary requests visible in target logs | TLS, web metadata, and one router fingerprint profile on at most four ports |
| Port scan (administrators, confirmed authorization) | Connection attempts against 1,000 ports | Nmap TCP connect scan of the top 1,000 ports with light service detection |

Even passive requests reveal the investigated subject to third-party services and originate from the server's
address. A VPN for the worker and `tools` is advisable before researching third-party targets; see
[TODO.md](../TODO.md).

## Authorization for active checks

Active-light, active enrichment, and port scans are available to administrators only. The administrator confirms
for every run that they are authorized, for example as owner, by assignment, or by court order. No target needs to
be registered in advance. The selected level is stored with the analysis and shown in the PDF. Only publicly
routable targets are contacted; for hostnames, every A and AAAA record must be public, and the connection is pinned
to the validated address.

## `tools` container

- Uses a dedicated Docker network without database or Redis access, a read-only filesystem, no Linux capabilities,
  `no-new-privileges`, and memory and process limits.
- Requires `TOOLS_TOKEN` for every request.
- Rejects non-public targets, including LAN, loopback, Docker, link-local, and CGNAT ranges.
- Connects only to IP addresses already resolved and validated by the worker, preventing DNS rebinding. Web
  requests are limited to at most four explicitly selected ports. For hostnames, all A and AAAA records are checked
  and `--resolve` pins the request to the selected target IP.
- Router requests do not follow redirects, limit bodies to 64 KiB, and send neither credentials nor login attempts.
  The generic profile requests only `/`; FRITZ!Box adds only BoxInfo; Speedport adds only `/data/Status.json` and
  retains allowlisted model and firmware fields. There are no exploit, CVE, or vulnerability probes. BoxInfo XML
  containing a DTD or entities is rejected, and serial numbers are never exposed.
- Port scanning uses a fixed profile and permits one scan at a time.

The container does not decide who may scan. Anyone holding its token could request a scan of an arbitrary public
target, so the token must remain only in `.env`.

## Accounts and authentication

- No open registration: administrators invite new accounts, and email addresses must be confirmed.
- Three failed attempts from one client address cause a one-hour lockout. `TRUSTED_PROXIES` allows the application
  to identify the actual client behind a reverse proxy.
- Sessions expire after 14 days. Cookies require HTTPS when `DJANGO_SECURE_COOKIES=1`.

## Handling third-party data

- Search and registry text is treated as data when sent to the language model. The system prompt instructs the
  model to ignore instructions embedded in source content.
- PDF export never loads external resources, preventing tracking pixels from cited pages.
- The PWA share target only prefills the search field and never starts an analysis automatically.
- Public email and phone web searches retrieve search-index metadata without opening result pages. These searches
  do not require an authorization confirmation. Active network probes keep the boundaries described above.
