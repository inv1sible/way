# Quellen

Alle Quellen laufen parallel; eine fehlgeschlagene Quelle erscheint mit Fehlermeldung in den Rohdaten und hält
die anderen nicht auf. Quellen mit API-Key sind aktiv, sobald der Key in `.env` steht (danach
`docker compose up -d`, damit die Container ihn übernehmen). Alle genannten Keys gibt es kostenlos.

## Rufnummern

| Quelle | Key | Inhalt |
|---|---|---|
| libphonenumber | – | Land, Ortsnetz, Typ (Mobil, Festnetz, Sonderrufnummer), ursprünglicher Netzbetreiber |
| Bundesnetzagentur-Maßnahmenliste | – | Ob gegen die Nummer Maßnahmen verhängt wurden (Abschaltung, Rechnungslegungsverbot) |
| Clever Dialer | – | Bewertungen und Spam-Einstufung |
| Websuche (SearXNG) | – | Fundstellen in üblichen Schreibweisen; nur Treffer, die die Nummer wirklich enthalten |
| Spam-Portale und Telefonbücher | – | Gezielte Suche auf bekannten Bewertungsportalen |

## IP-Adressen

| Quelle | Key (`.env`) | Inhalt |
|---|---|---|
| Reverse DNS, RDAP | – | Name zur Adresse, Netzinhaber, Abuse-Kontakt |
| WHOIS, ASN (Team Cymru) | – | lokal über den `tools`-Container (whois, dig) |
| ip-api.com | – | Standort, ASN, Hinweise auf Hosting/Proxy/Mobilfunk |
| Shodan InternetDB | – | Offene Ports und bekannte Schwachstellen aus Shodans Scans |
| GreyNoise Community | `GREYNOISE_KEY` (optional) | Ob die Adresse das Internet scannt; ohne Key mit niedrigem Limit |
| Tor-Exit-Liste | – | Offizielle Liste des Tor-Projekts |
| Spamhaus ZEN | – | DNS-Sperrlisten; braucht einen eigenen Resolver (öffentliche Resolver werden abgewiesen) |
| AbuseIPDB | `ABUSEIPDB_KEY` | Missbrauchsmeldungen, Vertrauenswert, Nutzungsart (z. B. Festnetz-Provider) |
| AlienVault OTX | `OTX_KEY` (optional) | Threat-Feeds (Pulses), in denen die Adresse vorkommt |
| VirusTotal | `VIRUSTOTAL_KEY` | Bewertung durch rund 90 Sicherheitsdienste |
| abuse.ch ThreatFox, URLhaus | `ABUSECH_KEY` | Malware-Infrastruktur und Schadsoftware-URLs |
| CrowdSec CTI | `CROWDSEC_KEY` | Beobachtete Angriffe und Einstufung aus dem CrowdSec-Netz |
| Censys | `CENSYS_TOKEN` | Dienste und Zertifikate aus Censys' Internet-Scans |
| Frühere eigene Analysen | – | Vergleich mit früheren Läufen derselben Abfrage |

Mit Datum ("Stand") zusätzlich: BGP-Historie (RIPEstat) und Passive DNS (AlienVault OTX).

## Hostnamen

Erst DNS-Auflösung, DNS-Einträge (dig) und Domain-WHOIS, Reputation des Namens (OTX, VirusTotal, ThreatFox,
URLhaus), dann alle IP-Quellen für die aufgelöste Adresse. Mit "leise aktiv" zusätzlich TLS-Zertifikat und
Web-Kopfzeilen (Ports 80 und 443), mit "Portscan" nmap.

## API-Keys besorgen

| Dienst | Registrierung | Hinweise |
|---|---|---|
| VirusTotal | <https://www.virustotal.com/gui/join-us> | Key im Profil unter "API Key"; 4 Abfragen/Minute, 500/Tag |
| abuse.ch | <https://auth.abuse.ch/> | Ein Key für ThreatFox und URLhaus |
| CrowdSec | <https://app.crowdsec.net/> | CTI-API-Key anlegen |
| AbuseIPDB | <https://www.abuseipdb.com/register> | Key unter Account → API |
| Censys | <https://platform.censys.io/> | Personal Access Token unter Account → API. Gratis: 100 Credits/Monat; `CENSYS_ORG_ID` beim Gratis-Konto **leer lassen** (sonst die UUID der Organisation, nicht ihr Name). `CENSYS_MONTHLY_LIMIT` begrenzt die Abfragen. |
| AlienVault OTX | <https://otx.alienvault.com/> | Optional, höhere Limits |
| GreyNoise | <https://viz.greynoise.io/signup> | Optional, höhere Limits |

## Bekannte Eigenheiten

- **AlienVault OTX** beendet Antworten bei Komprimierung oder Keep-Alive nicht sauber; die Abfragen laufen deshalb
  unkomprimiert mit `Connection: close` und einem zweiten Versuch.
- **ip-api.com** stuft manche dynamischen Endkunden-Adressen als "hosting" ein; AbuseIPDBs Nutzungsart ist hier
  verlässlicher.
- **Spamhaus PBL** ("Endkunden-Adressbereich laut Provider") ist kein Missbrauchsnachweis, sondern normal für
  private Anschlüsse.
