# Sicherheit und Opsec

## Abfragestufen

| Stufe | Kontakt zum Ziel | Quellen |
|---|---|---|
| passiv (Standard) | keiner; nur Registries, DNS und Drittdienste | RDAP, WHOIS, ASN, DNS-Einträge, Reputationsdienste |
| leicht aktiv (nur Admins, Berechtigung bestätigt, eigenes System) | wenige normale Zugriffe, erscheinen im Log des Ziels | TLS, Web-Metadaten, generischer Router- oder defensiver FRITZ!Box-Fingerprint auf höchstens 4 Ports |
| Portscan (nur Admins, nur eigene Systeme) | Verbindungsversuche auf 1000 Ports | nmap (`-sT`, Top-1000-TCP, leichte Diensterkennung) |

Auch passive Abfragen verraten den Drittdiensten, wofür man sich interessiert, und gehen von der Adresse des
Servers aus. Für Recherchen zu fremden Zielen ist ein VPN für Worker und `tools` sinnvoll (siehe
[TODO.md](../TODO.md)).

## Eigene Systeme

Portscan und jede aktive Anreicherung laufen nur für Ziele unter Admin → "Eigene Systeme": öffentliche IP, Netz bis
/22 bzw. /56, oder ein exakter Hostname. Ein Hostname beweist nicht, wem die Adresse gehört, auf die er zeigt (CDN,
Cloud, geänderter DNS-Eintrag). Bei Hostnamen ist deshalb die AS-Nummer des Netzes Pflicht, und gescannt wird nur,
wenn alle aufgelösten Adressen in diesem Netz liegen. Dasselbe gilt für jede aktive Anreicherung eines Hostnamens:
Alle A-/AAAA-Antworten müssen öffentlich sein und aktuell zu mindestens einem hinterlegten Origin-ASN passen.
Die geprüfte Adresse wird dann fest an die Verbindung gebunden. Der Bericht hebt diese dynamische Zielbindung
ausdrücklich als indirekten, zeitgebundenen Nachweis hervor – sie ist keine unveränderliche Geräteidentität.
Geprüft wird beim Absenden und noch einmal im Worker.

Die Detailseite kann ein eigenes System direkt aus den Rohdaten der geöffneten Analyse anlegen. Sie schlägt aktuelle
DNS-Adressen, Provider-Kontext und ASNs nur vor; das Öffnen löst keine neue Anfrage aus und die Person mit
Admin-Recht muss Eigentum bzw. Berechtigung bestätigen. Der Providername ist Dokumentation. Ein hinterlegter ASN ist
bei Hostnamen Pflicht und bei IP-Einträgen optional: Ist er vorhanden, sperrt WAY eine aktive Anreicherung, sobald die
aktuell abgefragte IP nicht mehr zu einem erwarteten ASN gehört. Auch das ist eine Sicherheitsgrenze, kein
Eigentumsnachweis.

Für einen IP-Eintrag kann zusätzlich ein bestätigter DNS-Name gespeichert werden. Reverse DNS ist nur eine
Vorbelegung, kein Vertrauenssignal. Vor einer aktiven Anfrage muss der Name aktuell die konkrete IP enthalten; alle
DNS-Antworten müssen öffentlich sein. Die Verbindung bleibt auf die ursprünglich geprüfte IP beschränkt.

## `tools`-Container

- Eigenes Docker-Netz ohne Datenbank und Redis, Dateisystem schreibgeschützt, keine Capabilities,
  `no-new-privileges`, Speicher- und Prozessgrenzen.
- Zugriff nur mit `TOOLS_TOKEN`.
- Lehnt alles ab, was keine öffentliche Adresse ist (LAN, Loopback, Docker-Netz, Link-Local, CGNAT).
- Verbindet sich nur zu IP-Adressen, die der Worker bereits aufgelöst hat (kein DNS-Rebinding); Web-Abfragen nur
  auf höchstens vier ausdrücklich gewählten Ports. Bei Hostnamen werden alle A/AAAA-Adressen geprüft und die
  Verbindung mit `--resolve` an die validierte Ziel-IP gebunden.
- Router- und FRITZ!Box-Abrufe folgen keinen Redirects, sind auf 64 KiB begrenzt und senden weder Zugangsdaten noch
  Anmeldeversuche. Das generische Router-Profil ruft nur `/` ab; nur das ausdrücklich gewählte FRITZ!Box-Profil
  fragt zusätzlich BoxInfo ab. Das Speedport-Profil fragt nur `/data/Status.json` ab und übernimmt daraus
  ausschließlich erlaubte Modell- und Firmwarefelder. Es gibt keine Exploit-, CVE- oder Schwachstellenproben.
  BoxInfo-XML mit DTD/Entities wird verworfen; Geräte-Seriennummern werden nie ausgegeben.
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
