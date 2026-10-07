# Bedienung

## Suche

Ins Suchfeld kommt eine Rufnummer (beliebige Schreibweise, ohne Ländervorwahl gilt `DEFAULT_REGION`), eine
IPv4-/IPv6-Adresse oder ein Hostname, auch als URL (`https://example.org/pfad` wird zu `example.org`).

Die Optionen erscheinen erst, wenn man ins Suchfeld klickt (und bleiben sichtbar, solange eine gesetzt ist):

- **Stand (optional):** Rückblick auf ein Datum. Zusätzlich kommen BGP-Historie (welches Netz hat die Adresse an
  dem Tag angekündigt, RIPEstat), Passive DNS (AlienVault OTX) und die eigene Analyse, die dem Datum am nächsten
  liegt. Passive DNS ist lückenhaft; wer eine dynamische Adresse zu einem Zeitpunkt nutzte, weiß nur der Provider.
- **Leise aktiv** (nur Admins): TLS-Zertifikat und Web-Kopfzeilen direkt vom Ziel. Das ist ein normaler Zugriff
  und erscheint im Log des Ziels.
- **Portscan** (nur Admins): nmap auf die Top-1000-Ports, nur für Ziele aus der Liste "Eigene Systeme"
  (siehe [sicherheit.md](sicherheit.md)).

"Analysieren" startet die Analyse und öffnet die Detailseite.

## Verlauf

Die Startseite listet die eigenen Analysen (Admins sehen alle). Wiederholte Analysen derselben Abfrage stehen
als ein Eintrag mit Zähler (z. B. `3×`), gezeigt wird die neueste. Gleichzeitig gestartete Analysen stehen
alphabetisch. Hinter der Abfrage steht in Klammern die Notiz, hinter dem Status das Risiko.

**Löschen:** Lange auf einen Eintrag drücken (oder "Auswählen"), weitere antippen, dann "Löschen". Ein Eintrag
umfasst alle Läufe dieser Abfrage. Laufende Analysen lassen sich erst nach dem Abschluss löschen.

## Detailseite

- **Symbolleiste neben dem Titel:** Notiz (Stift; gefüllt, wenn eine Notiz existiert), PDF herunterladen,
  erneut analysieren (mit denselben Optionen). PDF und erneut analysieren erscheinen nach dem Abschluss.
- **Weitere Analysen dieser Abfrage:** Aufklappliste aller anderen Läufe. Jeder Lauf zeigt aufgeklappt, was sich
  gegenüber dem Lauf davor geändert hat (z. B. `abuseipdb_score: 0 → 40`, Risiko, Adressen, offene Ports), und
  hat am Ende "Öffnen".
- **Seit der vorigen Analyse geändert:** erscheint nur, wenn sich etwas Messbares geändert hat.
- **Bericht:** Kurzfazit, Risikoeinschätzung, Erkenntnisse mit Quellenangabe, Empfehlungen. Die KI erhält nur die
  gesammelten Daten; Fundstellen aus der Websuche stehen zusätzlich als Liste darunter.
- **Rohdaten:** jede Quelle einzeln aufklappbar und kopierbar, "Alle kopieren" für alles zusammen.

Während eine Analyse läuft, aktualisiert sich die Seite selbst (Fortschritt, neue Quellen, Bericht).

## Auf dem Handy

Die Seite lässt sich als App installieren ("Zum Startbildschirm hinzufügen"). Danach erscheint "Who Are You" im
Teilen-Menü: Eine geteilte Nummer, ein Link oder eine Visitenkarte (`.vcf`) aus Telefon- oder Kontakte-App füllt
das Suchfeld vor. Gestartet wird erst nach Tippen auf "Analysieren", damit fremde Links keine Analysen auslösen.

## Konten

Admins laden neue Benutzer unter "Einladungen" per E-Mail ein (Link 7 Tage gültig); die E-Mail-Adresse wird
bestätigt, Anmeldung mit E-Mail oder Benutzername. Nach 3 Fehlversuchen ist die Anmeldung von dieser Adresse
eine Stunde gesperrt. "Passwort vergessen" funktioniert, sobald Mailversand eingerichtet ist.
