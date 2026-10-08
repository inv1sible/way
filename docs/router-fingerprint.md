# Router Fingerprint

Die Detailseite kann eine abgeschlossene passive Analyse gezielt anreichern. Das Plus-Symbol erscheint nur für
Admins und nur dann, wenn die untersuchte IP oder der Hostname unter **Admin → Eigene Systeme** eingetragen ist.
Vor dem Start muss die Berechtigung noch einmal ausdrücklich bestätigt werden. Jeder aktive Lauf wird separat
gespeichert und lässt sich dadurch klar vom passiven Ausgangslauf unterscheiden.

## Profile

- **Generischer Router:** Pro explizit freigegebenem Port (Vorgabe: `443`) wird sequenziell ein TLS-Handshake sowie
  eine HEAD- und, bei Textinhalt, eine GET-Anfrage für `/` ausgeführt. Ausgewertet werden nur Status, ausgewählte
  Header und Seitentitel. Allgemeine Begriffe wie „Router“, „Gateway“, „Modem“ oder „Speedport“ sind lediglich ein
  vorsichtiges Indiz; WAY nennt daraus keinen Hersteller, kein Modell und keine Firmwareversion.
- **FRITZ!Box:** Verwendet dasselbe geringe Web-Budget und fragt zusätzlich, nur ohne Anmeldung,
  `/jason_boxinfo.xml` ab. Details und Grenzen stehen im [FRITZ!Box Fingerprint](fritzbox-fingerprint.md).
- **Speedport (experimentell):** Prüft zusätzlich ausschließlich `/data/Status.json`. Aus der Antwort werden nur
  ausdrücklich erlaubte Modell- und Firmware-Felder übernommen; alle übrigen Statusdaten werden verworfen. Das
  Profil versucht keine Anmeldung, Challenge-Response-Logik, TR-064- oder weitere Statuspfade. Der Pfad ist je
  Modell, Firmware und WAN-Konfiguration optional und häufig nur aus dem LAN erreichbar.

Höchstens vier Ports und ein Timeout von 2 bis 20 Sekunden sind zulässig. Redirects sind deaktiviert; bei einem
Hostnamen bindet WAY SNI und HTTP-Host an die bereits geprüfte IP-Adresse. Die Ablaufpolitik wird als
`requestPolicy` in den Rohdaten sichtbar.

## Was bewusst nicht geschieht

Es gibt keine Login-Versuche, Zugangsdaten, Brute Force, automatische Portsuche, SOAP-Aktionen, Exploits,
CVE-/Schwachstellenproben oder automatische Folgeanfragen an andere Hosts. Eine aktive Prüfung erzeugt wenige
normale Webzugriffe und kann deshalb im Zielprotokoll sichtbar sein. Für fremde Systeme bleibt die Analyse passiv.

Ein offener Webport kann auf ein weitergeleitetes internes Gerät zeigen; bei IPv6 kann die Adresse selbst ein
internes Gerät sein. Ohne von außen erreichbaren Dienst ist eine Firmwareversion normalerweise nicht feststellbar.
