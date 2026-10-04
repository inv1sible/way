"""Datenquellen. Jede Quelle liefert {"source", "ok", "data"|"error"}."""

import inspect

import httpx

USER_AGENT = "who-are-you/0.1"


async def run_source(name, fn, *args):
    try:
        data = fn(*args)
        if inspect.isawaitable(data):
            data = await data
    except Exception as exc:  # eine ausgefallene Quelle darf den Bericht nicht verhindern
        return {"source": name, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"source": name, "ok": True, "data": data}


async def collect(kind, query):
    from . import host, ip, phone

    collector = {"ip": ip.collect, "host": host.collect, "phone": phone.collect}[kind]
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}) as client:
        return await collector(client, query)
