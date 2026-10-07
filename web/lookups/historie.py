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


def _exact(sources, name):
    return next((s.get("data") for s in sources if s.get("ok") and s["source"] == name), None)


def _reputation(sources):
    """Bewertungen der Reputationsdienste. Nur Quellen, die in der Analyse liefen: Fehlt ein Key oder
    scheiterte die Abfrage, fehlt das Merkmal und zählt nicht als Änderung."""
    found = {}
    if abuse := _exact(sources, "AbuseIPDB"):
        found["abuseipdb_score"] = abuse.get("abuseConfidenceScore")
        found["abuseipdb_meldungen"] = abuse.get("totalReports")
    for name, prefix in (("VirusTotal", "virustotal"), ("VirusTotal (Hostname)", "virustotal_name")):
        if stats := (_exact(sources, name) or {}).get("last_analysis_stats"):
            found[f"{prefix}_boesartig"] = stats.get("malicious")
            found[f"{prefix}_verdaechtig"] = stats.get("suspicious")
    if crowdsec := _exact(sources, "CrowdSec CTI"):
        found["crowdsec_reputation"] = crowdsec.get("reputation")
    if greynoise := _exact(sources, "GreyNoise Community"):
        found["greynoise"] = greynoise.get("classification") or ("Scanner" if greynoise.get("noise") else "nicht beobachtet")
    for name, key in (("AlienVault OTX", "otx_pulses"), ("AlienVault OTX (Hostname)", "otx_name_pulses")):
        if otx := _exact(sources, name):
            found[key] = otx.get("pulse_anzahl")
    for name, key in (("abuse.ch ThreatFox", "threatfox_treffer"), ("abuse.ch ThreatFox (Hostname)", "threatfox_name_treffer")):
        if threatfox := _exact(sources, name):
            found[key] = len(threatfox.get("treffer") or [])
    for name, key in (("abuse.ch URLhaus", "urlhaus_urls"), ("abuse.ch URLhaus (Hostname)", "urlhaus_name_urls")):
        if urlhaus := _exact(sources, name):
            found[key] = urlhaus.get("url_anzahl")
    if spamhaus := _exact(sources, "Spamhaus ZEN"):
        found["spamhaus"] = ", ".join(spamhaus.get("listen") or []) if spamhaus.get("gelistet") else "nicht gelistet"
    if tor := _exact(sources, "Tor-Exit-Liste"):
        found["tor_exit"] = "ja" if tor.get("tor_exit_node") else "nein"
    if shodan := _exact(sources, "Shodan InternetDB"):
        found["shodan_ports"] = sorted(shodan.get("ports") or [])
    if censys := _exact(sources, "Censys (Internet-Scan-Daten)"):
        found["censys_dienste"] = sorted(d.get("port") for d in censys.get("dienste", []) if d.get("port")) or censys.get("anzahl_dienste")
    return found


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
    found.update(_reputation(sources))
    return {key: value for key, value in found.items() if value not in (None, [], "")}


def _show(value):
    return ", ".join(map(str, value)) if isinstance(value, list) else str(value)


def _changed(before, after):
    """Nur Merkmale, die in beiden Analysen vorliegen: Ein fehlendes Merkmal heißt meist nur, dass die Stufe
    (z. B. Portscan) nicht lief, nicht dass sich etwas geändert hat."""
    return sorted(key for key in set(before) & set(after) if before[key] != after[key])


def compare(before_sources, after_sources):
    """Änderungen zwischen zwei Analysen als Liste (Merkmal, vorher, jetzt)."""
    before, after = facts(before_sources), facts(after_sources)
    return [(key, _show(before[key]), _show(after[key])) for key in _changed(before, after)]


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
