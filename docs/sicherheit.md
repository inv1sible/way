# Sicherheit und Opsec

## Abfragestufen

| Stufe | Kontakt zum Ziel | Quellen |
|---|---|---|
| passiv (Standard) | keiner; nur Registries, DNS und Drittdienste | RDAP, WHOIS, ASN, DNS-Einträge, Reputationsdienste |
| leise aktiv (nur Admins) | ein normaler Zugriff, erscheint im Log des Ziels | TLS-Zertifikat (openssl), Web-Kopfzeilen (curl, Port 80 und 443) |
| Portscan (nur Admins, nur eigene Systeme) | Verbindungsversuche auf 1000 Ports | nmap (`-sT`, Top-1000-TCP, leichte Diensterkennung) |

Auch passive Abfragen verraten den Drittdiensten, wofür man sich interessiert, und gehen von der Adresse des
Servers aus. Für Recherchen zu fremden Zielen ist ein VPN für Worker und `tools` sinnvoll (siehe
[TODO.md](../TODO.md)).

## Eigene Systeme

Der Portscan läuft nur für Ziele unter Admin → "Eigene Systeme": öffentliche IP, Netz bis /22 bzw. /56, oder ein
exakter Hostname. Ein Hostname beweist nicht, wem die Adresse gehört, auf die er zeigt (CDN, Cloud, geänderter
DNS-Eintrag). Bei Hostnamen ist deshalb die AS-Nummer des Netzes Pflicht, und gescannt wird nur, wenn alle
aufgelösten Adressen in diesem Netz liegen. Geprüft wird beim Absenden und noch einmal im Worker.

## `tools`-Container

- Eigenes Docker-Netz ohne Datenbank und Redis, Dateisystem schreibgeschützt, keine Capabilities,
  `no-new-privileges`, Speicher- und Prozessgrenzen.
- Zugriff nur mit `TOOLS_TOKEN`.
- Lehnt alles ab, was keine öffentliche Adresse ist (LAN, Loopback, Docker-Netz, Link-Local, CGNAT).
- Verbindet sich nur zu IP-Adressen, die der Worker bereits aufgelöst hat (kein DNS-Rebinding); Web-Abfragen nur
  auf Ports 80, 443, 8080 und 8443.
- Portscan mit festem Profil, ein Scan zur Zeit.

Der Container kennt die Liste der eigenen Systeme nicht: Wer das Token hat, kann beliebige öffentliche Ziele
scannen. Das Token gehört deshalb nur in `.env`.

## Konten und Anmeldung

- Kein offenes Registrieren: neue Konten nur per Einladung eines Admins, mit E-Mail-Bestätigung.
- Login-Sperre nach 3 Fehlversuchen für eine Stunde, je Client-Adresse (über `TRUSTED_PROXIES` die echte Adresse
  hinter dem Proxy).
- Sitzungen laufen nach 14 Tagen ab; Cookies nur über HTTPS (`DJANGO_SECURE_COOKIES=1`).

## Umgang mit Fremddaten

- Texte aus Suchergebnissen und Registern gehen als Daten an die KI; der Systemprompt weist sie an, darin
  enthaltene Anweisungen zu ignorieren.
- Der PDF-Export lädt keine externen Ressourcen (keine Tracking-Pixel aus Fundstellen).
- Das Teilen-Ziel der App füllt das Suchfeld nur vor und startet keine Analyse.
- Keine Suche nach Rufnummern in Leak-Daten (Datenschutz, § 202d StGB).
