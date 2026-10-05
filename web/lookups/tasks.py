import asyncio
import logging

from celery import shared_task
from celery.signals import worker_ready
from django.conf import settings
from django.db import connection
from django.utils import timezone

from . import llm
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


async def _collect_with_progress(lookup):
    """Sammelt die Quellen und speichert jede, sobald sie fertig ist (Zwischenstand für die Oberfläche)."""
    lock, done = asyncio.Lock(), []

    async def on_result(result):
        async with lock:
            done.append(result)
            await asyncio.to_thread(_save_sources, lookup.pk, list(done))

    return await collect(lookup.kind, lookup.query, on_result=on_result)


@shared_task
def run_lookup(lookup_id):
    lookup = Lookup.objects.get(pk=lookup_id)
    try:
        _update(lookup, status=Lookup.Status.COLLECTING, model=settings.OSINT_OLLAMA_MODEL)
        sources = asyncio.run(_collect_with_progress(lookup))
        _update(lookup, status=Lookup.Status.ANALYZING, sources=sources)
        report = llm.write_report(lookup.kind, lookup.query, sources)
        _update(
            lookup,
            status=Lookup.Status.DONE,
            report_md=report,
            risk=llm.extract_risk(report),
            finished_at=timezone.now(),
        )
    except Exception as exc:
        log.exception("Analyse %s fehlgeschlagen", lookup_id)
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
