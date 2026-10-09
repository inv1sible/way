# Data sources

Sources run concurrently. A failed source appears with its error in raw data and does not stop the others. A source
requiring an API key becomes active once the key is present in `.env`; run `docker compose up -d` afterward so the
containers receive it. All listed services offer a free access option.

## Phone numbers

| Source | Key | Data |
|---|---|---|
| libphonenumber | – | Country, area code, type such as mobile, landline, or premium rate, and original carrier |
| German Federal Network Agency measures | – | Published measures against the number, such as disconnection or billing prohibition |
| Clever Dialer | – | Community ratings and spam classification |
| Web search through SearXNG | – | References using common number formats; results must actually contain the number |
| Main-number detection | – | Limited checks of plausible German landline organization prefixes, assuming four or five extension digits and exceptionally six; derived queries are neither stored nor highlighted, and published organization numbers remain separate from the specific extension |
| Spam directories and phone books | – | Targeted searches of known rating and directory sites |

## IP addresses

| Source | Key in `.env` | Data |
|---|---|---|
| Reverse DNS and RDAP | – | Address name, network owner, and abuse contact |
| WHOIS and ASN through Team Cymru | – | Local `whois` and `dig` execution in the `tools` container |
| ip-api.com | – | Location, ASN, and hosting, proxy, or mobile-network indicators |
| Shodan InternetDB | – | Open ports and known vulnerabilities from Shodan observations |
| GreyNoise Community | `GREYNOISE_KEY` (optional) | Whether the address scans the internet; lower limits without a key |
| Tor exit list | – | Official Tor Project list |
| Spamhaus ZEN | – | DNS blocklists; requires a private resolver because public resolvers are rejected |
| AbuseIPDB | `ABUSEIPDB_KEY` | Abuse reports, confidence score, and usage type such as fixed-line ISP |
| AlienVault OTX | `OTX_KEY` (optional) | Threat-intelligence pulses containing the address |
| VirusTotal | `VIRUSTOTAL_KEY` | Assessments by approximately 90 security services |
| abuse.ch ThreatFox and URLhaus | `ABUSECH_KEY` | Malware infrastructure and malicious URLs |
| CrowdSec CTI | `CROWDSEC_KEY` | Observed attacks and CrowdSec network classification |
| Censys | `CENSYS_TOKEN` | Services and certificates from Censys internet observations |
| FRITZ!Box Fingerprint | – | Passive AVM/FRITZ! indicators and, after authorization, a few direct web requests |
| Previous own analyses | – | Comparison with earlier runs of the same query |

Selecting a reference date additionally adds BGP history from RIPEstat and passive DNS from AlienVault OTX.

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
| Censys | <https://platform.censys.io/> | Create a personal access token under Account → API. The free plan includes 100 credits/month. Leave `CENSYS_ORG_ID` empty for an individual free account; otherwise use the organization UUID, not its name. `CENSYS_MONTHLY_LIMIT` caps calls. |
| AlienVault OTX | <https://otx.alienvault.com/> | Optional key for higher limits |
| GreyNoise | <https://viz.greynoise.io/signup> | Optional key for higher limits |

## Known behavior

- **AlienVault OTX** sometimes fails to terminate compressed or keep-alive responses correctly. WAY therefore
  requests uncompressed responses with `Connection: close` and permits one retry.
- **ip-api.com** classifies some dynamic residential addresses as hosting. AbuseIPDB's usage type can be more useful
  for this distinction.
- **Spamhaus PBL** means that the provider identifies the range as an end-user address pool. It is normal for
  residential connections and is not evidence of abuse.
