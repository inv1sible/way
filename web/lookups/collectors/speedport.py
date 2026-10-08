"""Defensiver Speedport-Fingerprint über einen optionalen, unauthentifizierten Statuspfad."""

import ipaddress
from datetime import datetime, timezone

from . import fritzbox, tools

SOURCE = "Speedport Fingerprint"
DEFAULT_PORTS = [80, 443]


def build(target, resolved_address, direct=None, active_blocked=None, active_error=None):
    address = ipaddress.ip_address(resolved_address)
    timestamp = datetime.now(timezone.utc).isoformat()
    direct = direct or {}
    status = direct.get("speedport") or {}
    device = status.get("device") or {"vendor": None, "model": None, "rawFirmwareVersion": None}
    observations = []
    for item in direct.get("observations", []):
        observations.append({
            "source": "direct", "timestamp": timestamp,
            "evidence": str(item.get("evidence", "Speedport-Merkmal erkannt."))[:300], "sensitive": False,
        })
    if status.get("plausible"):
        observations.append({
            "source": "direct", "timestamp": timestamp,
            "evidence": "/data/Status.json lieferte ein direktes Speedport-Modellfeld.", "sensitive": False,
        })
    warnings = list(direct.get("warnings") or [])
    if active_error:
        warnings.append(f"Leichte aktive Prüfung nicht vollständig möglich: {active_error}")
    if active_blocked:
        warnings.append(active_blocked)
    direct_status = bool(status.get("plausible"))
    marker = bool(observations)
    return {
        "target": {
            "input": target, "resolvedAddress": str(address), "addressFamily": f"IPv{address.version}",
            "publiclyRoutable": fritzbox.public_address(str(address)),
        },
        "authorization": {
            "activeChecksConfirmed": True,
            "activeChecksPerformed": bool(direct and not active_blocked),
        },
        "classification": {
            "likelySpeedport": direct_status or marker,
            "confidence": "high" if direct_status else "low" if marker else "none",
            "reasons": [item["evidence"] for item in observations],
        },
        "summary": (
            "Speedport sehr wahrscheinlich: öffentlich lesbares Statusfeld nennt ein Speedport-Modell."
            if direct_status else
            "Ein einzelnes Speedport-Merkmal wurde erkannt; Modell und Firmware bleiben unbestätigt."
            if marker else
            "Kein belastbarer direkter Hinweis auf einen Speedport gefunden."
        ),
        "device": device,
        "services": direct.get("services", []),
        "tls": direct.get("tls") or {
            "certificateSubject": None, "certificateIssuer": None, "dnsNames": [], "trusted": None,
            "validFrom": None, "validTo": None,
        },
        "observations": observations,
        "limitations": [
            "Der Statuspfad ist modell-, firmware- und WAN-konfigurationsabhängig und oft nur im LAN verfügbar.",
            "Ein offener Port kann auf ein weitergeleitetes internes Gerät statt auf einen Speedport zeigen.",
            "Eine 401-, 403-, 404- oder Login-Antwort ist ein normales negatives Ergebnis.",
            "Es werden keine Anmeldung, Challenge-Response-, TR-064- oder weiteren Statusanfragen ausgeführt.",
        ],
        "warnings": list(dict.fromkeys(warnings)),
        "requestPolicy": direct.get("requestPolicy", ""),
    }


async def fingerprint(client, target, address, ports=None, timeout=8, active_blocked=None):
    if active_blocked:
        return build(target, address, active_blocked=active_blocked)
    direct = None
    error = None
    try:
        direct = await tools.speedport(client, address, sni=target if target != address else None,
                                       ports=ports or DEFAULT_PORTS, timeout=timeout)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    return build(target, address, direct=direct, active_error=error)
