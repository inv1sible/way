# Data sources

Sources run concurrently. A failed source appears with its error in raw data and does not stop the others. A source
requiring an API key becomes active once the key is present in `.env`; run `docker compose up -d` afterward so the
containers receive it. Availability and free allowances depend on the provider; HIBP's exact email API is paid.

## Phone numbers

| Source | Key | Data |
|---|---|---|
| libphonenumber | – | Country, area code, type such as mobile, landline, or premium rate, and original carrier |
| German Federal Network Agency measures | – | Published measures against the number, such as disconnection or billing prohibition |
| Clever Dialer | – | Community ratings and spam classification |
| Public web search through SearXNG | Explicit user option | Up to three searches using common number formats; results must actually contain the number; result pages are never opened or crawled |
| Main-number detection | – | Limited checks of plausible German landline organization prefixes, assuming four or five extension digits and exceptionally six; derived queries are neither stored nor highlighted, and published organization numbers remain separate from the specific extension |
| Spam directories and phone books | – | Targeted searches of known rating and directory sites |

## Email addresses

Email analysis uses only exact-address queries and preserves the configured source limits.

| Source | Key | Data |
|---|---|---|
| Have I Been Pwned v3 | `HIBP_API_KEY` | Published breach metadata for the exact address, capped and cached for 24 hours; no pastes, passwords, messenger/social-account lookups, or domain enumeration |
| Public web references via SearXNG | Explicit user option | Up to two exact-address searches; retains matching public result metadata, does not open or crawl result pages, excludes messenger, people-directory, paste, and leak domains, and may include a public professional-profile snippet |

A breach exposure does not establish the identity of a person, ownership of an account, or a current compromise.
Use it to reset affected passwords, enable MFA, and review the affected service.

## IP addresses

| Source | Key in `.env` | Data |
|---|---|---|
| Reverse DNS and RDAP | – | Address name, network owner, and abuse contact |
| WHOIS and ASN through Team Cymru | – | Local `whois` and `dig` execution in the `tools` container |
| ip-api.com | – | Location, ASN, and hosting, proxy, or mobile-network indicators |
| IPinfo.io Lite | `IPINFO_TOKEN` | Country, continent, ASN, AS organization name, and AS domain |
| Shodan InternetDB | – | Open ports and known vulnerabilities from Shodan observations |
| GreyNoise Community | `GREYNOISE_KEY` (optional) | Whether the address scans the internet; lower limits without a key |
| Tor exit list | – | Official Tor Project list |
| Spamhaus ZEN | – | DNS blocklists; requires a private resolver because public resolvers are rejected |
| AbuseIPDB | `ABUSEIPDB_KEY` | Abuse reports, confidence score, and usage type such as fixed-line ISP |
| AlienVault OTX | `OTX_KEY` (optional) | Threat-intelligence pulses containing the address |
| VirusTotal | `VIRUSTOTAL_KEY` | Assessments by approximately 90 security services |
| VirusTotal resolution history | `VIRUSTOTAL_KEY` | Up to 20 historical IP-to-hostname observations with full UTC timestamps, cached for 24 hours; not a device or subscriber identifier |
| abuse.ch ThreatFox and URLhaus | `ABUSECH_KEY` | Malware infrastructure and malicious URLs |
| CrowdSec CTI | `CROWDSEC_KEY` | Observed attacks and CrowdSec network classification |
| Censys | `CENSYS_TOKEN` | Services and certificates from Censys internet observations |
| Shodan Host API | `SHODAN_API_KEY` | Capped, cached passive host observations, banners, timestamps, and hostnames; complements the keyless InternetDB response |
| Netlas | `NETLAS_API_KEY` | Capped, cached public-index host summary (PTR, network context, and observed ports) |
| FRITZ!Box Fingerprint | – | Passive AVM/FRITZ! indicators and, after authorization, a few direct web requests |
| Previous own analyses | – | Comparison with earlier runs of the same query |

Selecting a reference date additionally adds BGP history from RIPEstat and passive DNS from AlienVault OTX.
With `VIRUSTOTAL_KEY`, IP analyses also include up to 20 cached historical IP-to-hostname observations on every run.

## Hostnames

WAY resolves DNS, retrieves DNS records and domain WHOIS, checks hostname reputation through OTX, VirusTotal,
ThreatFox, and URLhaus, and then runs the IP sources for the selected resolved address. Active-light can add TLS,
web metadata, and the selected router profile. Port scan can add Nmap for an authorized owned target.

## Obtaining API keys

| Service | Registration | Notes |
|---|---|---|
| VirusTotal | <https://www.virustotal.com/gui/join-us> | Available under **API Key** in the profile; free limits include 4 requests/minute and 500/day |
| abuse.ch | <https://auth.abuse.ch/> | One key covers ThreatFox and URLhaus |
| CrowdSec | <https://app.crowdsec.net/> | Create a CTI API key |
| AbuseIPDB | <https://www.abuseipdb.com/register> | Available under Account → API |
| IPinfo.io Lite | <https://ipinfo.io/signup> | The free Lite API requires a token and returns country-level location plus basic ASN data. WAY sends the token in an authorization header, not in the URL. IPinfo.io attribution is retained in every raw result. |
| Censys | <https://platform.censys.io/> | Create a personal access token under Account → API. The free plan includes 100 credits/month. Leave `CENSYS_ORG_ID` empty for an individual free account; otherwise use the organization UUID, not its name. `CENSYS_MONTHLY_LIMIT` caps calls. |
| Have I Been Pwned | <https://haveibeenpwned.com/API/V3> | A paid API key is required for exact email breach checks. Use only with ownership or explicit authorization; HIBP domain search additionally requires verified domain control. |
| Shodan | <https://developer.shodan.io/api> | Optional Host API key. `SHODAN_MONTHLY_LIMIT` caps calls; InternetDB remains available without a key. |
| Netlas | <https://docs.netlas.io/api-reference/> | Optional Host Info key. WAY uses only the public index and a minimal field set; `NETLAS_MONTHLY_LIMIT` caps calls. |
| AlienVault OTX | <https://otx.alienvault.com/> | Optional key for higher limits |
| GreyNoise | <https://viz.greynoise.io/signup> | Optional key for higher limits |

## Known behavior

- **AlienVault OTX** sometimes fails to terminate compressed or keep-alive responses correctly. WAY therefore
  requests uncompressed responses with `Connection: close` and permits one retry.
- **ip-api.com** classifies some dynamic residential addresses as hosting. AbuseIPDB's usage type can be more useful
  for this distinction.
- **IPinfo.io Lite** identifies the network's autonomous system, not the subscriber or device using an address.
  Its location is country-level and the provider is queried only when `IPINFO_TOKEN` is configured.
- **Passive scanner data** is third-party evidence measured at another time. It can show an Internet-facing IoT
  service or a forwarded internal device, but cannot inventory a LAN, establish router ownership, or prove that an
  IP address is static. Use a verified hostname and repeated owned-target observations to follow dynamic addresses.
- **SearXNG web search** depends on the upstream engines that answer at that moment. WAY preserves the responding
  and unavailable engines in raw data, caches results for 24 hours, and does not bypass CAPTCHAs or engine blocks.
- **Spamhaus PBL** means that the provider identifies the range as an end-user address pool. It is normal for
  residential connections and is not evidence of abuse.
