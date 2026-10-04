import asyncio
import logging

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from . import llm
from .collectors import collect
from .models import Lookup

log = logging.getLogger(__name__)


def _update(lookup, **fields):
    for name, value in fields.items():
        setattr(lookup, name, value)
    lookup.save(update_fields=list(fields))


@shared_task
def run_lookup(lookup_id):
    lookup = Lookup.objects.get(pk=lookup_id)
    try:
        _update(lookup, status=Lookup.Status.COLLECTING, model=settings.OSINT_OLLAMA_MODEL)
        sources = asyncio.run(collect(lookup.kind, lookup.query))
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
