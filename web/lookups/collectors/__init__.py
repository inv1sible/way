"""Datenquellen. Jede Quelle liefert {"source", "ok", "data"|"error"}."""

import contextvars
import inspect
import logging

import httpx

log = logging.getLogger(__name__)
USER_AGENT = "who-are-you/0.1"

# Wird von collect() gesetzt; run_source meldet jede fertige Quelle sofort dorthin, damit die
# Oberfläche Zwischenstände zeigen kann.
_on_result = contextvars.ContextVar("on_result", default=None)


async def run_source(name, fn, *args):
    try:
        data = fn(*args)
        if inspect.isawaitable(data):
            data = await data
        result = {"source": name, "ok": True, "data": data}
    except Exception as exc:  # eine ausgefallene Quelle darf den Bericht nicht verhindern
        result = {"source": name, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    callback = _on_result.get()
    if callback:
        try:
            await callback(result)
        except Exception:
            log.exception("Fortschrittsmeldung für %s fehlgeschlagen", name)
    return result


async def collect(kind, query, on_result=None, active=False, active_ports=None, active_timeout=8, active_profile="fritzbox",
                  scan=False, scan_asns=None, active_asns=None, active_dns_name=None, as_of=None, email_public_web=False,
                  phone_public_web=False):
    from . import email, host, ip, phone

    _on_result.set(on_result)

    collector = {"email": email.collect, "ip": ip.collect, "host": host.collect, "phone": phone.collect}[kind]
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}) as client:
        extra = {}
        if kind not in {"phone", "email"}:
            extra.update(active_ports=active_ports, active_timeout=active_timeout, active_profile=active_profile)
        if kind == "ip":
            extra["active_asns"] = active_asns
            extra["active_dns_name"] = active_dns_name
        if kind == "host":
            extra["scan_asns"] = scan_asns
            extra["active_asns"] = active_asns
        if kind == "email":
            extra["public_web"] = email_public_web
        if kind == "phone":
            extra["public_web"] = phone_public_web
        return await collector(client, query, active=active, scan=scan, as_of=as_of, **extra)
