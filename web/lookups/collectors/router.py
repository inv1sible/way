"""Kleiner, herstellerneutraler Router-Fingerprint für ausdrücklich freigegebene Systeme."""

import ipaddress
from datetime import datetime, timezone

from . import fritzbox, tools

SOURCE = "Router Fingerprint"
DEFAULT_PORTS = [443]


def _limitations():
    return [
        "Ein offener Port kann auf ein weitergeleitetes internes Gerät statt auf den Router zeigen.",
        "Bei IPv6 kann die untersuchte Adresse zu einem internen Gerät statt zum Router gehören.",
        "Ohne erreichbaren WAN-Webdienst ist eine Zuordnung von Hersteller, Modell oder Firmware von außen meist nicht möglich.",
        "Allgemeine Router-/Gateway-Wörter sind nur Indizien und beweisen weder Hersteller noch Modell.",
    ]


def build(target, resolved_address, direct=None, active_blocked=None, active_error=None):
    """Formt ausschließlich direkt belegte Web- und TLS-Metadaten in das WAY-Schema um."""
    address = ipaddress.ip_address(resolved_address)
    timestamp = datetime.now(timezone.utc).isoformat()
    direct = direct or {}
    observations = [
        {
            "source": "direct", "timestamp": timestamp,
            "evidence": str(item.get("evidence", "Router-/Gateway-Merkmal erkannt."))[:300],
            "sensitive": False,
        }
        for item in direct.get("observations", [])
    ]
    warnings = list(direct.get("warnings") or [])
    if active_error:
        warnings.append(f"Leichte aktive Prüfung nicht vollständig möglich: {active_error}")
    if active_blocked:
        warnings.append(active_blocked)
    likely = bool(observations)
    return {
        "target": {
            "input": target,
            "resolvedAddress": str(address),
            "addressFamily": f"IPv{address.version}",
            "publiclyRoutable": fritzbox.public_address(str(address)),
        },
        "authorization": {
            "activeChecksConfirmed": True,
            "activeChecksPerformed": bool(direct and not active_blocked),
        },
        "classification": {
            "likelyRouter": likely,
            # Ein einzelner Titel/Header ist absichtlich kein starker Gerätebeweis.
            "confidence": "low" if likely else "none",
            "reasons": [item["evidence"] for item in observations],
        },
        "summary": (
            "Router-/Gateway-Oberfläche wahrscheinlich: direktes HTTP-Metadatenmerkmal erkannt."
            if likely else
            "Kein belastbarer direkter Hinweis auf eine Router-/Gateway-Oberfläche gefunden."
        ),
        # Kein Herstelleradapter darf dieses Profil zum Raten über Modell oder Firmware verleiten.
        "device": {"vendor": None, "model": None, "firmwareVersion": None},
        "services": direct.get("services", []),
        "tls": direct.get("tls") or {
            "certificateSubject": None, "certificateIssuer": None, "dnsNames": [], "trusted": None,
            "validFrom": None, "validTo": None,
        },
        "observations": observations,
        "limitations": _limitations(),
        "warnings": list(dict.fromkeys(warnings)),
        "requestPolicy": direct.get("requestPolicy", ""),
    }


async def fingerprint(client, target, address, ports=None, timeout=8, active_blocked=None):
    if active_blocked:
        return build(target, address, active_blocked=active_blocked)
    direct = None
    error = None
    try:
        direct = await tools.router(client, address, sni=target if target != address else None,
                                    ports=ports or DEFAULT_PORTS, timeout=timeout)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    return build(target, address, direct=direct, active_error=error)
