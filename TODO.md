# To-do

Status: 2026-10-05. Items within each section are ordered by recommendation.

## VPN and operational security (planned as the next step)

All requests currently originate from the home IP address, including third-party APIs, web searches, and the
`tools` container. This is acceptable for analyses of owned systems and passive lookups, but not for direct
contact with third-party targets.

- [ ] Select a VPN provider. Recommendation: Mullvad; alternative: IVPN; Proton VPN Free only for evaluation.
- [ ] Configure `gluetun`: route the `tools` container and worker through the VPN with a kill switch, while
      permitting access to Redis, PostgreSQL, and Ollama on the LAN through `FIREWALL_OUTBOUND_SUBNETS`.
- [ ] Route DNS requests for Spamhaus, Team Cymru, and name resolution through the VPN as well; otherwise they
      disclose the investigated targets.
- [ ] Test web search through the VPN separately because search engines often throttle VPN addresses more quickly.
- [ ] Consider Tor only for level 1 TLS/web requests, not APIs, because exit nodes are frequently blocked.
- [ ] Improve third-party privacy by preferring local datasets: GeoLite2 instead of ip-api.com, local cloud and VPN
      ranges, and local FireHOL lists.
- [ ] Add defense in depth for `tools`: a `DOCKER-USER` firewall rule that prevents the `way_probe` network from
      reaching the LAN. At present this is enforced only by target validation inside the service.
- [ ] Define retention and rotation for `tools` logs because they contain queried targets.
- [ ] Establish the rule that level 1 and level 2 contact with third-party targets requires the VPN first.

## User actions

- [ ] Add SMTP credentials to `.env` (`EMAIL_*`). Invitation and confirmation messages are not delivered until
      then.
- [ ] Add an email address to the `admin` account so that password reset works.
- [ ] Free approximately 3 GB of GPU memory on `192.168.1.139` so `qwen3:8b` fits completely on the GPU.
- [ ] Add free API keys to `.env`: VirusTotal, abuse.ch, CrowdSec, and AbuseIPDB.
- [ ] Create a free account at platform.censys.io, set `CENSYS_TOKEN` and the organization ID, run an analysis,
      verify the response parsing, and determine the credit cost. Censys has so far only been tested with example
      data; adjust `CENSYS_MONTHLY_LIMIT` afterward.
- [ ] Add a local DNS record for the public domain pointing to `192.168.1.200`. Without it, all LAN devices appear
      as `192.168.1.1` and share the login lockout.
- [ ] Review the port-scan findings for the owned address: are SSH and ports 6789, 8080, or 8443 internet-accessible?

## Additional sources

- [ ] Add a watch list with daily snapshots for selected names and addresses so history does not depend on manual
      analyses, for example to record daily address changes of a FRITZ!Box.
- [ ] Historical date: add VirusTotal resolutions when a key is available, the Wayback Machine when operational,
      and RIPEstat historical WHOIS if it provides useful versions.
- [ ] Level 0: passive DNS through OTX and CIRCL, RIPEstat/BGP context, Certificate Transparency through crt.sh,
      and SANS ISC.
- [ ] Domains and email: ransomware.live, Hudson Rock, Intelligence X, and Have I Been Pwned. Do not operate custom
      onion crawlers or search leaked datasets for phone numbers because of privacy and German Criminal Code
      section 202d.
- [ ] Phone numbers: add more search engines while keeping results visible per engine, and provide a focused
      “Who is behind this?” view that highlights name-bearing sources separately.
- [ ] Schedule recurring checks of an owned phone number and notify the owner about new references.

## Features and operations

- [ ] Add a cryptographic ownership challenge for hostnames through DNS TXT or a file instead of relying only on
      origin-AS validation.
- [ ] The `tools` container does not know the owned-system list. Anyone with its token can scan arbitrary public
      targets. Consider signed per-scan authorization or validating a local allowlist in the container.
- [ ] Extend port scanning to registered networks and optionally add further profiles for owned systems.
- [ ] Add two-factor authentication and consider per-username lockouts without enabling denial-of-service lockouts.
- [ ] Back up PostgreSQL and `.env`.
- [ ] Build an Android app only if caller identification while the phone rings is required; the PWA already covers
      sharing from other apps.
