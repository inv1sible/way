"""PDF-Bericht einer Analyse mit WeasyPrint."""

import re

from django.template.loader import render_to_string
from django.utils import timezone
from weasyprint import HTML

from .templatetags.report_tags import history_data, scan_data
from weasyprint.urls import URLFetcher


def block_external(url, *args, **kwargs):
    """Keine Netzwerkzugriffe beim Rendern: Der KI-Text kann Bild- oder Link-URLs aus fremden
    Quellen enthalten, die der Server sonst selbst abrufen würde."""
    raise ValueError(f"Externe Ressourcen sind im PDF nicht erlaubt: {url[:80]}")


class BlockingFetcher(URLFetcher):
    """Lehnt jeden Abruf ab, auch file:// (sonst könnten lokale Dateien ins PDF gelangen)."""

    def fetch(self, url, headers=None):
        block_external(url)


def filename(lookup, language="de"):
    query = re.sub(r"[^A-Za-z0-9.+-]+", "_", lookup.query).strip("_")[:60]
    return f"way-{lookup.kind}-{query}-{language}-{timezone.localtime(lookup.created_at):%Y%m%d-%H%M}.pdf"


def render(lookup, request):
    html = render_to_string(
        "lookups/report_pdf.html",
        {"lookup": lookup, "generated_at": timezone.now(), "scan": scan_data(lookup.sources),
         "history": history_data(lookup.sources)},
        request=request,
    )
    return HTML(string=html, url_fetcher=BlockingFetcher(allowed_protocols=())).write_pdf()
