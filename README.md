# Who Are You (WAY)

Selbst gehostetes OSINT-Werkzeug: Rufnummer, IP-Adresse oder Hostnamen eingeben und einen Bericht mit
Risikoeinschätzung erhalten. Die Daten kommen ohne KI aus freien Quellen (Registries, DNS, Reputationsdienste,
Websuche); ein lokales Sprachmodell über [Ollama](https://ollama.com) fasst sie zusammen. Nichts verlässt den
eigenen Server außer den Abfragen an die Quellen selbst.

- **Rufnummern:** Land, Ortsnetz, Netzbetreiber, Maßnahmenliste der Bundesnetzagentur, Bewertungen und Fundstellen
  im Netz (über eine selbst gehostete SearXNG-Suche).
- **IP-Adressen und Hostnamen:** Netzinhaber, Standort, DNS, Reputation (VirusTotal, AbuseIPDB, CrowdSec,
  GreyNoise, AlienVault OTX, abuse.ch, Spamhaus), Internet-Scan-Daten (Shodan, Censys); optional TLS-Zertifikat,
  Web-Kopfzeilen und Portscan eigener Systeme.
- **Verlauf:** Wiederholte Analysen derselben Abfrage werden gruppiert und verglichen (geänderte Adressen, Ports,
  Reputation, Risiko). Optional ein Rückblick auf ein Datum (BGP- und Passive-DNS-Historie).
- **Oberfläche:** Deutsch, mobil als installierbare Web-App (PWA) mit Teilen-Ziel, Live-Fortschritt, PDF-Export,
  Notizen, Mehrbenutzer mit Einladungen.

## Schnellstart

Voraussetzungen: Docker mit Compose und ein erreichbarer Ollama-Server mit einem Modell (getestet mit `qwen3:8b`).

```sh
cp .env.example .env    # Secrets, Passwörter, OLLAMA_URL setzen; API-Keys optional
docker compose up -d --build
```

Die Web-UI läuft unter `http://<host>:${APP_PORT}`. Der Benutzer aus `DJANGO_SUPERUSER_*` wird beim ersten
Start angelegt, weitere Benutzer lädt man unter "Einladungen" ein.

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/bedienung.md](docs/bedienung.md) | Suche, Optionen, Verlauf, Detailseite, Notizen, Teilen auf dem Handy |
| [docs/quellen.md](docs/quellen.md) | Alle Datenquellen, welche einen API-Key brauchen und wo es ihn gibt |
| [docs/betrieb.md](docs/betrieb.md) | Installation, Konfiguration (`.env`), Reverse Proxy, Ollama, Updates, Backups |
| [docs/architektur.md](docs/architektur.md) | Dienste, Ablauf einer Analyse, Datenmodell, Live-Aktualisierung |
| [docs/sicherheit.md](docs/sicherheit.md) | Abfragestufen, `tools`-Container, eigene Systeme, Konten, Opsec |
| [TODO.md](TODO.md) | Offene Punkte und Pläne |

## Tests

```sh
docker compose run --rm web python manage.py test lookups accounts
docker compose run --rm --no-deps -e TOOLS_TOKEN=x tools python -m unittest -v
```

## Rechtliches

Gedacht für die Prüfung unbekannter Anrufer und eigener Systeme. Aktive Abfragen (TLS, Web-Kopfzeilen) und
Portscans fremder Ziele können je nach Land unzulässig sein; der Portscan ist deshalb auf eingetragene eigene
Systeme beschränkt. Die Nutzungsbedingungen der einzelnen Quellen gelten.
