"""Verlauf einer Abfrage aus den bereits gespeicherten Analysen desselben Nutzers.

Bewusst auch für Admins nur die eigenen: Der Verlauf wird im Bericht gespeichert und darf keine Daten
anderer Nutzer enthalten (z. B. wenn jemand später keine Admin-Rechte mehr hat). Ohne Eigentümer gibt es
keinen Verlauf (verweigern statt alles zeigen)."""

from datetime import date

from django.utils import timezone

from .models import Lookup

HISTORY_SOURCE = "Frühere eigene Analysen"
MAX_LISTED = 10
MAX_CONSIDERED = 30


def _data(sources, prefix):
    return next((s.get("data") for s in sources if s.get("ok") and s["source"].startswith(prefix)), None)


def facts(sources):
    """Messbare Merkmale einer Analyse, die sich im Lauf der Zeit ändern können."""
    found = {}
    if dns := _data(sources, "DNS-Auflösung"):
        found["adressen"] = sorted(dns.get("adressen") or [])
    if rdns := _data(sources, "Reverse DNS"):
        found["reverse_dns"] = rdns.get("ptr")
    if asn := _data(sources, "ASN"):
        found["asn"] = sorted(asn.get("asn") or [])
    if tls := _data(sources, "TLS-Zertifikat"):
        found["zertifikat_sha256"] = tls.get("sha256")
    if scan := _data(sources, "Portscan"):
        found["offene_ports"] = sorted(p["port"] for p in scan.get("offen", []))
    if bnetza := _data(sources, "Bundesnetzagentur"):
        found["massnahmenliste_treffer"] = len(bnetza.get("treffer", []))
    if clever := _data(sources, "Clever Dialer"):
        found["clever_dialer_bewertungen"] = clever.get("bewertungen")
    return {key: value for key, value in found.items() if value not in (None, [], "")}


def _show(value):
    return ", ".join(map(str, value)) if isinstance(value, list) else str(value)


def _changed(before, after):
    """Nur Merkmale, die in beiden Analysen vorliegen: Ein fehlendes Merkmal heißt meist nur, dass die Stufe
    (z. B. Portscan) nicht lief, nicht dass sich etwas geändert hat."""
    return sorted(key for key in set(before) & set(after) if before[key] != after[key])


def own_history(lookup, sources, as_of=None):
    if lookup.created_by_id is None:
        return None
    previous = Lookup.objects.filter(
        kind=lookup.kind, query=lookup.query, status=Lookup.Status.DONE, created_by_id=lookup.created_by_id
    ).exclude(pk=lookup.pk)
    older = list(previous.order_by("-created_at")[:MAX_CONSIDERED])[::-1]
    if not older:
        return None

    entries, last = [], None
    for item in older:
        current = facts(item.sources)
        local = timezone.localtime(item.created_at)
        entry = {"analyse": item.pk, "datum": local.strftime("%Y-%m-%d %H:%M"), "anzeige": local.strftime("%d.%m.%Y %H:%M"),
                 "risiko": item.risk or None, "fakten": {k: _show(v) for k, v in current.items()}}
        if last is not None:
            entry["geaendert"] = _changed(last, current)
        entries.append(entry)
        last = current

    now = facts(sources)
    result = {
        "anzahl_frueherer_analysen": len(older),
        "analysen": entries[-MAX_LISTED:],
        "aenderungen_seit_letzter_analyse": {
            key: {"vorher": _show(last[key]), "jetzt": _show(now[key])} for key in _changed(last, now)
        },
        "letzte_analyse": entries[-1]["datum"],
        "letzte_analyse_anzeige": entries[-1]["anzeige"],
    }
    if as_of:
        def distance(entry):
            return abs((date.fromisoformat(entry["datum"][:10]) - as_of).days)
        nearest = min(entries, key=distance)
        result["naechste_zum_stichtag"] = {"analyse": nearest["analyse"], "datum": nearest["datum"],
                                           "anzeige": nearest["anzeige"],
                                           "abstand_tage": distance(nearest), "fakten": nearest["fakten"]}
    return result
