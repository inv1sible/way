import asyncio
import logging

from celery import shared_task
from celery.signals import worker_ready
from django.conf import settings
from django.db import connection
from django.utils import timezone

from . import historie, llm
from .collectors import collect
from .models import Lookup

log = logging.getLogger(__name__)


def _update(lookup, **fields):
    for name, value in fields.items():
        setattr(lookup, name, value)
    lookup.save(update_fields=list(fields))


def _save_sources(lookup_id, sources):
    Lookup.objects.filter(pk=lookup_id).update(sources=sources)
    connection.close()  # der Thread aus asyncio.to_thread behält sonst seine Verbindung


async def _collect_with_progress(lookup, active=False, scan=False):
    """Sammelt die Quellen und speichert jede, sobald sie fertig ist (Zwischenstand für die Oberfläche)."""
    lock, done = asyncio.Lock(), []

    async def on_result(result):
        async with lock:
            done.append(result)
            await asyncio.to_thread(_save_sources, lookup.pk, list(done))

    return await collect(
        lookup.kind, lookup.query, on_result=on_result, active=active,
        active_ports=lookup.active_ports, active_timeout=lookup.active_timeout,
        active_profile=lookup.active_profile,
        scan=scan, as_of=lookup.as_of,
        email_public_web=lookup.email_public_web,
        phone_public_web=lookup.phone_public_web,
        local_only=lookup.local_only,
    )


@shared_task
def run_lookup(lookup_id):
    lookup = Lookup.objects.get(pk=lookup_id)
    try:
        _update(lookup, status=Lookup.Status.COLLECTING, model=settings.OSINT_OLLAMA_MODEL)
        sources = asyncio.run(_collect_with_progress(lookup, active=lookup.active_probe, scan=lookup.port_scan))
        if past := historie.own_history(lookup, sources, lookup.as_of):
            sources.append({"source": historie.HISTORY_SOURCE, "ok": True, "data": past})
        _update(lookup, status=Lookup.Status.ANALYZING, sources=sources)
        report = llm.write_report(lookup.kind, lookup.query, sources, as_of=lookup.as_of)
        report = llm.append_web_findings(report, sources)
        _update(
            lookup,
            status=Lookup.Status.DONE,
            report_md=report,
            risk="",
            finished_at=timezone.now(),
        )
    except Exception as exc:
        log.exception("Analyse %s fehlgeschlagen", lookup_id)
        _update(lookup, status=Lookup.Status.FAILED, error=f"{type(exc).__name__}: {exc}", finished_at=timezone.now())


@shared_task
def run_compare(lookup_id):
    """Vergleichsbericht aus den gespeicherten Ergebnissen; keine neuen Abfragen, nur das lokale Sprachmodell."""
    lookup = Lookup.objects.get(pk=lookup_id)
    try:
        _update(lookup, status=Lookup.Status.ANALYZING, model=settings.OSINT_OLLAMA_MODEL)
        members = list(lookup.compared.order_by("created_at"))
        if len(members) < 2:
            raise RuntimeError("Für einen Vergleich sind mindestens zwei vorhandene Analysen nötig.")
        _update(lookup, status=Lookup.Status.DONE, report_md=llm.write_comparison(members), finished_at=timezone.now())
    except Exception as exc:
        log.exception("Vergleich %s fehlgeschlagen", lookup_id)
        _update(lookup, status=Lookup.Status.FAILED, error=f"{type(exc).__name__}: {exc}", finished_at=timezone.now())


@worker_ready.connect
def fail_interrupted_lookups(**kwargs):
    """Analysen, die beim Start eines Workers noch als laufend markiert sind, wurden durch einen
    Neustart unterbrochen; ohne Markierung stünden sie bis zur erneuten Zustellung (1 h) still."""
    interrupted = Lookup.objects.filter(status__in=[Lookup.Status.COLLECTING, Lookup.Status.ANALYZING])
    count = interrupted.update(
        status=Lookup.Status.FAILED,
        error="Abgebrochen durch Neustart des Workers. Bitte erneut analysieren.",
        finished_at=timezone.now(),
    )
    if count:
        log.warning("%s unterbrochene Analyse(n) als fehlgeschlagen markiert", count)
