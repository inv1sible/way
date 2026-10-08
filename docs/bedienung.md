# Bedienung

## Suche

Ins Suchfeld kommt eine Rufnummer (beliebige Schreibweise, ohne Ländervorwahl gilt `DEFAULT_REGION`), eine
IPv4-/IPv6-Adresse oder ein Hostname, auch als URL (`https://example.org/pfad` wird zu `example.org`).

Die Optionen erscheinen erst, wenn man ins Suchfeld klickt (und bleiben sichtbar, solange eine gesetzt ist):

- **Stand (optional):** Rückblick auf ein Datum. Zusätzlich kommen BGP-Historie (welches Netz hat die Adresse an
  dem Tag angekündigt, RIPEstat), Passive DNS (AlienVault OTX) und die eigene Analyse, die dem Datum am nächsten
  liegt. Passive DNS ist lückenhaft; wer eine dynamische Adresse zu einem Zeitpunkt nutzte, weiß nur der Provider.
- **Leicht aktiv** (nur Admins, nur eingetragene eigene Systeme): Nach ausdrücklicher Bestätigung der Berechtigung
  TLS, Web-Metadaten und den öffentlichen FRITZ!Box-Endpunkt prüfen. Optional sind höchstens vier Web-Ports und ein
  kurzer Timeout einstellbar. Details: [FRITZ!Box Fingerprint](fritzbox-fingerprint.md) und
  [Router Fingerprint](router-fingerprint.md).
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
- **Sprache:** Der globale Schalter **DE | EN** in der Kopfzeile stellt die gesamte Oberfläche um. Er gilt auch
  für die Detailseite und den PDF-Download. Der gespeicherte KI-Bericht enthält beide Fassungen, angezeigt und
  heruntergeladen wird jeweils nur die gewählte Sprache. Historische Analysen mit ausschließlich einsprachigem
  KI-Bericht werden bei der zugehörigen Datenmigration entfernt.
- **FRITZ!Box Fingerprint:** Negative oder unsichere Ergebnisse erscheinen ausschließlich als technische Rohquelle.
  Nur ein positiver Nachweis wird vom KI-Bericht als Befund aufgegriffen. Die Rohdaten enthalten Ziel,
  Autorisierung, Dienste, TLS, Beobachtungen, Grenzen und Warnungen.
- **Eigenes System einrichten (zweites Plus-Symbol):** Admins können ein IP-Ziel oder einen Hostnamen direkt aus der
  Detailseite übernehmen. WAY schlägt aus den bereits vorhandenen Rohdaten aktuelle DNS-Adressen, Provider-Kontext
  und ASNs vor, ohne beim Öffnen etwas neu abzufragen. Zielwert und ASNs bleiben editierbar, das Speichern verlangt
  eine Berechtigungsbestätigung. Provider ist Dokumentation; ASNs sind die technische Sicherheitsgrenze. Bei einer
  IP mit gespeicherten ASNs wird eine aktive Anreicherung gesperrt, wenn die aktuelle IP nicht mehr dazu gehört.
  Für IPs kann außerdem ein bestätigter DNS-Name gespeichert werden (Reverse DNS wird nur vorgeschlagen): Vor einem
  aktiven Zugriff muss dieser Name weiterhin genau auf die IP auflösen.
- **Mehr Erkenntnisse gewinnen (Plus-Symbol):** Für Admins erscheint dies nach Abschluss bei einem Ziel aus
  „Eigene Systeme“. Es erzeugt einen getrennten Folgelauf. Das Profil **Generischer Router** fragt pro freigegebenem
  Port nur TLS sowie Header und Titel von `/` ab; **FRITZ!Box** ergänzt ausschließlich
  `/jason_boxinfo.xml`; **Speedport (experimentell)** nur `/data/Status.json`. Alle Profile sind sequenziell,
  folgen keinen Redirects und enthalten keine Anmeldung, Exploits oder Schwachstellenproben.
- **Dynamische Anschlüsse:** Trage für einen regelmäßig wechselnden Anschluss den exakten DynDNS- oder
  MyFRITZ!-Hostnamen statt der momentanen IP unter „Eigene Systeme“ ein, zusammen mit den erwarteten Provider-ASNs.
  Bei jeder aktiven Prüfung gleicht WAY sämtliche aktuellen DNS-Adressen mit diesen ASNs ab, pinnt die gewählte
  Adresse und hält die zeitgebundene Bindung in den Rohdaten fest. Ein ISP-Reverse-DNS ist dafür kein
  Eigentumsnachweis.
- **Rohdaten:** jede Quelle einzeln aufklappbar und kopierbar, "Alle kopieren" für alles zusammen.

## Durchwahlen und Zentralnummern

Bei deutschen Festnetznummern gleicht WAY zusätzlich wenige plausible Stammnummern ab: Die Ortsnetzkennzahl bleibt
erhalten, als Durchwahl werden vier oder fünf, ausnahmsweise sechs Endziffern angenommen. Im Teilnehmerteil der
Stammnummer bleiben mindestens zwei Ziffern. Die abgeleiteten Suchbegriffe werden weder gespeichert noch im Bericht
ausgegeben. Es gibt dafür keine hervorgehobene Ergebnis-Kachel; nachvollziehbare Evidenz bleibt ausschließlich bei
der jeweiligen Quelle. Dieser Abgleich soll veröffentlichte Zentralnummern etwa von Behörden, Hochschulen, Kliniken
und Unternehmen finden, ist aber kein Zuordnungsbeweis: Erst eine veröffentlichte Kontakt-/Impressumsnummer mit
Quelle, Fundstelle und Abrufzeit ist Evidenz für die Stammnummer. Sie belegt weder die konkrete Durchwahl noch die
Identität eines Anrufers. Teiltreffer innerhalb längerer Nummern werden verworfen. Tests verwenden ausschließlich
synthetische Beispieldaten und führen keine Netzabfragen aus.

Die Telefon-Websuche nutzt höchstens drei Anfragen: formatierte exakte Nummer, bei fehlendem Treffer die reine
Ziffernfolge und anschließend – sofern sinnvoll – eine Zentralnummern- oder Portal-Suche. Eine blockierte
Suchmaschine wird nicht umgangen.

Während eine Analyse läuft, aktualisiert sich die Seite selbst (Fortschritt, neue Quellen, Bericht).

## Auf dem Handy

Die Seite lässt sich als App installieren ("Zum Startbildschirm hinzufügen"). Danach erscheint "Who Are You" im
Teilen-Menü: Eine geteilte Nummer, ein Link oder eine Visitenkarte (`.vcf`) aus Telefon- oder Kontakte-App füllt
das Suchfeld vor. Gestartet wird erst nach Tippen auf "Analysieren", damit fremde Links keine Analysen auslösen.

## Konten

Admins laden neue Benutzer unter "Einladungen" per E-Mail ein (Link 7 Tage gültig); die E-Mail-Adresse wird
bestätigt, Anmeldung mit E-Mail oder Benutzername. Nach 3 Fehlversuchen ist die Anmeldung von dieser Adresse
eine Stunde gesperrt. "Passwort vergessen" funktioniert, sobald Mailversand eingerichtet ist.
