# Architektur

## Dienste

| Dienst | Aufgabe |
|---|---|
| `web` | Django (Gunicorn): Oberfläche, Login, Admin unter `/admin/`, PDF-Export |
| `worker` | Celery: fragt die Quellen ab und lässt den Bericht schreiben |
| `tools` | whois, dig, openssl, curl, nmap hinter einer schmalen Token-API; eigenes Netz, nur öffentliche Ziele |
| `db` | PostgreSQL |
| `redis` | Message-Broker für Celery |
| `searxng` | Selbst gehostete Metasuche für Rufnummern |
| Ollama | extern (`OLLAMA_URL`), schreibt den Bericht |

```
Browser ──HTTPS──> Reverse Proxy ──> web ──> db
                                      │       ▲
                                      ▼       │
                                    redis ──> worker ──> Quellen im Internet
                                              │  ├────> searxng
                                              │  ├────> tools (eigenes Netz) ──> Ziel
                                              │  └────> Ollama
```

## Ablauf einer Analyse

1. `web` erkennt die Art der Eingabe (`lookups/detect.py`), legt einen `Lookup` an und startet die Celery-Aufgabe
   nach dem Commit.
2. Der Worker (`lookups/tasks.py`) fragt alle Quellen parallel ab (`lookups/collectors/`, asyncio mit httpx).
   Jedes Ergebnis wird sofort gespeichert, damit die Seite es live zeigen kann.
3. Aus früheren Läufen derselben Abfrage desselben Nutzers entsteht die Quelle "Frühere eigene Analysen"
   (`lookups/historie.py`).
4. Die Rohdaten gehen, je Quelle gekürzt, an Ollama (`lookups/llm.py`). Der Bericht enthält gleichwertige deutsche
   und englische Abschnitte; die Zeile "Risiko: …" wird ausgelesen. Feste Regeln (z. B. auffällige offene Ports)
   können die Risikostufe in beiden Sprachfassungen anheben.
5. Status: Wartet → Quellen werden abgefragt → KI schreibt den Bericht → Fertig (oder Fehler).

## Datenmodell

- **`Lookup`:** Abfrage, Art, Status, Risiko, Rohdaten (`sources`, JSON-Liste mit `source`, `ok`, `data`/`error`),
  Bericht (Markdown), Notiz, Optionen (`as_of`, `active_probe`, `active_ports`, `active_timeout`, `port_scan`),
  Eigentümer.
- **`OwnedTarget`:** eigene Systeme für den Portscan (Adresse, Netz oder Hostname mit AS-Nummer).
- **`accounts`:** Einladungen und E-Mail-Bestätigung.

Sichtbarkeit: Nutzer sehen nur ihre eigenen Analysen, Admins alle. Der Vergleich mit früheren Läufen nutzt
immer nur die Analysen desselben Eigentümers.

## Live-Aktualisierung

Die Detailseite besteht aus Fragmenten (`templates/lookups/live/`). Während eine Analyse läuft, fragt
`static/lookups/live.js` alle paar Sekunden `/analyse/<id>/status/` ab. Der Server antwortet nur mit Fragmenten,
deren Hash sich geändert hat, und gar nichts rendert er, wenn sich der Zustand (`rev`) nicht geändert hat.

## Berichtsoberfläche

Neben dem KI-Bericht werden keine zusätzlichen Ergebnis-, Warn- oder Hinweisboxen gerendert. Technische Grenzen,
Sicherheitsentscheidungen und Quellenbefunde bleiben als Rohdaten nachvollziehbar und werden – wenn sie für die
Einordnung relevant sind – im KI-Bericht behandelt. Neue Quellen dürfen diese Regel nicht mit separaten Kacheln in
Detailansicht oder PDF umgehen.

## Vergleich von Läufen

`historie.facts()` zieht aus den Rohdaten messbare Merkmale: Adressen, Reverse DNS, ASN, TLS-Zertifikat, offene
Ports, Bundesnetzagentur- und Clever-Dialer-Treffer sowie die Reputationswerte (AbuseIPDB, VirusTotal, CrowdSec,
GreyNoise, OTX, abuse.ch, Spamhaus, Tor, Shodan- und Censys-Ports). Verglichen werden nur Merkmale, die in beiden
Läufen vorliegen: Fehlt ein Key oder scheiterte eine Quelle, ist das keine Änderung.

## Tests

`web/lookups/tests.py`, `web/accounts/tests.py` und `tools/test_app.py`. Netzwerkzugriffe sind in den Tests
durch Attrappen ersetzt (`httpx.MockTransport`, `mock.patch`).
