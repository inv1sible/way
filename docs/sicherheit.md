# Security and operational security

## Request levels

| Level | Contact with target | Sources |
|---|---|---|
| Passive (default) | None; registries, DNS, and third-party services only | RDAP, WHOIS, ASN, DNS records, and reputation services |
| Active-light (administrators, confirmed authorization, owned target) | A few ordinary requests visible in target logs | TLS, web metadata, and one router fingerprint profile on at most four ports |
| Port scan (administrators, owned targets only) | Connection attempts against 1,000 ports | Nmap TCP connect scan of the top 1,000 ports with light service detection |

Even passive requests reveal the investigated subject to third-party services and originate from the server's
address. A VPN for the worker and `tools` is advisable before researching third-party targets; see
[TODO.md](../TODO.md).

## Owned systems

Port scans and active enrichment run only for entries under Admin → **Owned systems**: a public IP address, a
network no broader than `/22` for IPv4 or `/56` for IPv6, or an exact hostname. A hostname alone does not prove who
owns its current address because it may use a CDN, cloud service, or changed DNS record. Hostname entries therefore
require expected origin ASNs. WAY proceeds only when every resolved address is public and currently belongs to one
of those ASNs. The worker repeats validation immediately before access and pins the selected address to the
connection. The report describes this as indirect, time-bound binding rather than immutable device identity.

Administrators can create owned-system entries from existing raw data on a detail page. WAY suggests observed DNS
addresses, provider context, and ASNs without issuing another request. Target and ASN values remain editable, and
saving requires explicit confirmation of ownership or authorization. Provider name is documentation. Expected ASN
is mandatory for hostname entries and optional for IP entries; when present, it blocks active enrichment if the IP
no longer belongs to an allowed ASN. This is a safety boundary, not proof of ownership.

An IP entry can additionally store a confirmed DNS name. Reverse DNS is only a suggested initial value and carries
no trust. Before active access, the name must still resolve to the exact IP and every result must be public. The
connection remains pinned to the originally validated address.

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

The container itself does not know the owned-system list. Anyone holding its token could request a scan of an
arbitrary public target, so the token must remain only in `.env`.

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
- WAY does not search leaked datasets for phone numbers because of privacy and German Criminal Code section 202d.
