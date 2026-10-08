# FRITZ!Box Fingerprint

WAY ergänzt IP- und Hostnamenanalysen um die strukturierte Quelle **FRITZ!Box Fingerprint**. Sie soll defensiv
einschätzen, ob das öffentlich erreichbare Ziel wahrscheinlich eine FRITZ!Box ist. Das Ergebnis ist eine
Momentaufnahme bzw. bei Suchmaschinen-Daten ein möglicherweise älterer Fremdbefund – kein Eigentumsnachweis und
keine Schwachstellenprüfung.

## Verwendung und Berechtigung

Im Normalfall genügt eine IP-Adresse oder ein Hostname im Suchfeld. Der Standardmodus ist **passiv** und kontaktiert
das Ziel nicht. Er wertet Reverse DNS sowie die ohnehin konfigurierten Shodan-InternetDB- und Censys-Ergebnisse auf
ausdrückliche AVM-/FRITZ!-Merkmale aus. Censys bleibt optional und benötigt den bereits vorhandenen
`CENSYS_TOKEN`; es wurde keine neue API-Abhängigkeit eingeführt.

Nur Admins sehen **Leicht aktiv**. Zusätzlich muss das Ziel unter „Eigene Systeme“ eingetragen sein; der Schalter ist
zugleich die ausdrückliche Bestätigung, dass das Ziel dem Nutzer gehört oder für die Prüfung freigegeben wurde.
Optional können 1 bis 4 Ports und ein Timeout von 2 bis 20 Sekunden angegeben werden. Ohne Portangabe prüft WAY
ausschließlich `443` und `8443`. `80` und `8080` werden als HTTP behandelt, alle anderen explizit genannten Ports
als HTTPS. Die Einstellung wird bei „Erneut analysieren“ erhalten. Eine passiv gestartete Analyse kann nach ihrem
Abschluss als separater, verknüpfter Folgelauf über „Mehr Erkenntnisse gewinnen“ angereichert werden.

Die aktive Prüfung arbeitet pro Port streng sequenziell. Sie prüft den Inhaltstyp zunächst mit HEAD und führt nur
für textuelle Antworten einen GET aus, insgesamt höchstens vier HTTP-Anfragen je Port:

1. `/` für HTTP-Status, ausgewählte Header und gegebenenfalls den Seitentitel,
2. `/jason_boxinfo.xml` für öffentlich ohne Anmeldung angebotene Geräteinformationen.

Es gibt keine Anmeldung, keine Zugangsdaten, keine SOAP-Aktion, keinen Brute-Force-, Exploit- oder CVE-Test und
keinen automatischen Portscan. Redirects werden nicht verfolgt. Der allgemeine, separat bestätigte Nmap-Portscan
von WAY bleibt unabhängig davon und ist weiterhin nur für eingetragene eigene Systeme verfügbar. Die
Nmap-Diensterkennung ist in der [Nmap-Dokumentation](https://nmap.org/book/man-version-detection.html) beschrieben.

## Zielbindung und Datenschutz

- IP-Literale und Hostnamen werden normalisiert und streng validiert.
- Nur öffentlich routbare Ziele sind aktiv zulässig. Loopback, private und reservierte Netze, Link-Local,
  Multicast, CGNAT, Dokumentationsnetze und Cloud-Metadatenadressen werden abgewiesen.
- Bei Hostnamen müssen **alle** A- und AAAA-Ergebnisse öffentlich sein. Schon eine interne Mischadresse sperrt die
  aktive Prüfung.
- Die geprüfte Adresse wird an den Werkzeugdienst übergeben und dort erneut validiert. `curl --resolve` bindet
  Hostheader und TLS-SNI an genau diese Adresse; dadurch findet während der Verbindung keine zweite DNS-Auflösung
  statt. IPv6-Literale werden in URLs korrekt geklammert.
- TLS-Zertifikate dürfen für das Fingerprinting selbstsigniert sein. WAY kennzeichnet sie als nicht vertrauenswürdig,
  deaktiviert die Zertifikatsprüfung aber nicht global.
- Antwortkörper sind auf 64 KiB begrenzt. Binäre Inhalte werden nicht ausgewertet. XML mit DTD oder Entities wird
  verworfen; die Geräteantwort wird weder roh gespeichert noch geloggt.
- Eine in BoxInfo enthaltene Geräte-Seriennummer wird immer vollständig verworfen. WAY besitzt derzeit keinen
  separaten sicheren Ausgabemodus für dieses sensible Detail.

## Ergebnis und Einstufung

Die Rohdatenquelle enthält `target`, `authorization`, `classification`, `device`, `services`, `tls`,
`observations`, `limitations`, `warnings` und eine verständliche `summary`. Fehlende Werte bleiben `null`.
Ein negativer oder unsicherer Fingerprint wird nur dort dokumentiert und nicht im KI-Bericht hervorgehoben. Ein
positiver Nachweis kann im zweisprachigen KI-Bericht erscheinen.

```json
{
  "classification": {
    "likelyFritzBox": true,
    "confidence": "high",
    "reasons": ["/jason_boxinfo.xml lieferte ein plausibles BoxInfo-Dokument; Geräteseriennummer wurde redigiert."]
  },
  "device": {
    "model": "FRITZ!Box 7590 AX",
    "hardwareId": "259",
    "fritzOsVersion": "8.02",
    "rawFirmwareVersion": "259.08.02-123456",
    "revision": "123456",
    "oem": "avm",
    "language": "de",
    "labBuild": "Labor"
  }
}
```

`high` setzt ein plausibles, erfolgreich geparstes BoxInfo-Dokument voraus. `medium` braucht mehrere unabhängige
Quellen, `low` bezeichnet ein einzelnes Indiz, `none` keinen belastbaren Hinweis. Modell und exakte Version werden
nur aus direkt gelieferten Feldern übernommen. Die Rohversion bleibt unverändert; eine FRITZ!OS-Version wird nur
aus einem eindeutigen AVM-Format abgeleitet.

`401`, `403`, `404`, Timeout, Login-HTML und nicht parsebares oder zu großes XML sind normale negative Ergebnisse.
`/jason_boxinfo.xml` ist **nicht** auf jeder FRITZ!Box und nicht über jeden WAN-Zugang erreichbar. Schnittstellen und
modellabhängige Hinweise veröffentlicht AVM unter [FRITZ!-Schnittstellen](https://fritz.com/pages/schnittstellen).

## Grenzen

- Eine öffentliche IPv4 kann wegen CGNAT oder DS-Lite beim Provider enden.
- Ein offener Port kann auf ein anderes internes Gerät weitergeleitet sein.
- Bei IPv6 kann die untersuchte Adresse zu einem internen Gerät statt zur FRITZ!Box gehören.
- Ohne erreichbaren WAN-Webdienst lässt sich die Firmware von außen normalerweise nicht feststellen.
- Shodan- und Censys-Daten können veraltet sein; WAY zeigt deshalb den Beobachtungs-/Abfragezeitpunkt und den
  entsprechenden Vorbehalt an.

Das Werkzeug ist ausschließlich für eigene oder ausdrücklich freigegebene Systeme bestimmt.
