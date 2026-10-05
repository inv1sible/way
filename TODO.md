# To-do

Stand: 2026-10-05. Reihenfolge innerhalb der Abschnitte = Empfehlung.

## VPN und Opsec (vom Nutzer als nächster Schritt vorgemerkt)

Bisher gehen alle Abfragen von der Heim-IP aus (Drittdienste, Websuche, `tools`-Container). Das ist für
Analysen eigener Systeme und passive Abfragen vertretbar, für fremde Ziele mit direktem Kontakt nicht.

- [ ] VPN-Anbieter wählen (Empfehlung: Mullvad, Alternative IVPN; ProtonVPN-Free nur zum Ausprobieren).
- [ ] `gluetun` einrichten: `tools`-Container und Worker durch das VPN leiten (Notaus eingebaut); Zugriff auf
      Redis, Datenbank und Ollama im LAN per `FIREWALL_OUTBOUND_SUBNETS` erlauben.
- [ ] DNS-Anfragen (Spamhaus, Team Cymru, Namensauflösung) mit durchs VPN leiten, sonst verraten sie die Ziele.
- [ ] Websuche (SearXNG) getrennt testen: VPN-Adressen werden von Suchmaschinen oft schneller gesperrt.
- [ ] Tor optional nur für Stufe 1 (TLS/Web), nicht für APIs (Exit-Nodes werden häufig geblockt).
- [ ] Datenschutz bei Drittdiensten: lokale Datenbanken statt Abfrage (GeoLite2 statt ip-api.com, Cloud- und
      VPN-Bereiche, FireHOL-Listen lokal).
- [ ] Defense in depth für `tools`: Firewall-Regel (`DOCKER-USER`), die dem Netz `way_probe` den Zugriff auf das
      LAN verbietet. Bisher verhindert das nur die Zielprüfung im Dienst selbst.
- [ ] Logs des `tools`-Containers enthalten die abgefragten Ziele: Aufbewahrung und Rotation festlegen.
- [ ] Regel festhalten: Stufe 1 und 2 gegen fremde Ziele erst nach Einführung des VPNs.

## Vom Nutzer zu erledigen

- [ ] SMTP-Zugangsdaten in `.env` (`EMAIL_*`); bis dahin gehen keine Einladungs-/Bestätigungsmails raus.
- [ ] `admin`-Konto im Admin eine E-Mail-Adresse geben (sonst kein "Passwort vergessen").
- [ ] Grafikspeicher auf 192.168.1.139 freimachen (ca. 3 GB), damit `qwen3:8b` komplett auf die GPU passt.
- [ ] Kostenlose API-Keys in `.env`: VirusTotal, abuse.ch, CrowdSec, AbuseIPDB.
- [ ] Censys: Gratis-Konto auf platform.censys.io, Token (`CENSYS_TOKEN`) und Organisations-ID eintragen, dann eine
      Analyse starten und prüfen, ob die Antwort richtig ausgewertet wird (bisher nur mit Beispieldaten getestet)
      und wie viele Credits eine Abfrage kostet (Obergrenze `CENSYS_MONTHLY_LIMIT` danach anpassen).
- [ ] Lokaler DNS-Eintrag für die Domain auf 192.168.1.200 (sonst erscheinen alle LAN-Geräte als 192.168.1.1
      und sperren sich gegenseitig bei Fehlanmeldungen).
- [ ] Portscan-Befund zur eigenen Adresse prüfen (SSH, Ports 6789/8080/8443 aus dem Internet erreichbar?).

## Weitere Quellen

- [ ] Beobachtungsliste: tägliche Schnappschüsse (Zeitplaner-Container) für ausgewählte Namen/Adressen, damit die
      Historie nicht von manuellen Analysen abhängt (z. B. tägliche Adresswechsel einer FritzBox).
- [ ] Stand-Datum: VirusTotal-Resolutions (mit Key), Wayback Machine (war beim Test offline), RIPEstat
      historical-whois (lieferte für ein /24 keine Versionen).

- [ ] Stufe 0: Passive DNS (OTX-Daten auswerten, CIRCL), RIPEstat/BGP-Kontext, Certificate Transparency (crt.sh),
      SANS ISC.
- [ ] Domains und E-Mail: ransomware.live, Hudson Rock (frei), Intelligence X und Have I Been Pwned (Registrierung).
      Keine eigenen Onion-Crawler und keine Telefonnummern-Suche in Leak-Daten (Datenschutz, §202d StGB).
- [ ] Rufnummern: weitere Suchmaschinen, Ergebnisse je Engine sichtbar halten; Ansicht "Wer steckt dahinter"
      (Fundstellen mit Namen getrennt hervorheben).
- [ ] Wiederkehrende Prüfung der eigenen Rufnummer (0170 1234567) mit Benachrichtigung bei neuen Fundstellen.

## Funktion und Betrieb

- [ ] Eigene Systeme direkt aus der Analyse-Seite eintragen (bisher nur im Admin).
- [ ] Echter Eigentumsnachweis für Hostnamen (Challenge per DNS-TXT oder Datei) statt nur Netzprüfung per AS-Nummer.
- [ ] Der `tools`-Container kennt die Liste der eigenen Systeme nicht; wer das Token hat, kann beliebige öffentliche
      Ziele scannen. Optional: signierte Freigabe je Scan oder Liste im Container prüfen.
- [ ] Portscan: Netze statt Einzeladresse, optional zusätzliche Profile (z. B. alle 65535 Ports) für eigene Systeme.
- [ ] Zwei-Faktor-Anmeldung; zusätzlich Sperre pro Benutzername bedenken (Abwägung: Aussperren durch Fremde).
- [ ] Backup der PostgreSQL-Daten und der `.env`.
- [ ] Android-App nur, wenn Anrufprüfung beim Klingeln gewünscht ist (die PWA deckt Teilen bereits ab).
