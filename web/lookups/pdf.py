"""PDF-Bericht einer Analyse mit WeasyPrint."""

import re

from django.template.loader import render_to_string
from django.utils import timezone
from weasyprint import HTML

from . import geo
from .templatetags.report_tags import geo_data, history_data, scan_data
from weasyprint.urls import URLFetcher, URLFetcherResponse


def block_external(url, *args, **kwargs):
    """Keine Netzwerkzugriffe beim Rendern: Der KI-Text kann Bild- oder Link-URLs aus fremden
    Quellen enthalten, die der Server sonst selbst abrufen würde."""
    raise ValueError(f"Externe Ressourcen sind im PDF nicht erlaubt: {url[:80]}")


class BlockingFetcher(URLFetcher):
    """Lehnt jeden Abruf ab, auch file:// (sonst könnten lokale Dateien ins PDF gelangen). Erlaubt sind nur
    selbst erzeugte Bilder unter way-asset:, z. B. die Standortkarte."""

    def __init__(self, assets=None, **kwargs):
        super().__init__(**kwargs)
        self.assets = assets or {}

    def fetch(self, url, headers=None):
        if url in self.assets:
            return URLFetcherResponse(url, body=self.assets[url], headers={"Content-Type": "image/png"})
        block_external(url)


def filename(lookup, language="de"):
    query = re.sub(r"[^A-Za-z0-9.+-]+", "_", lookup.query).strip("_")[:60]
    return f"way-{lookup.kind}-{query}-{language}-{timezone.localtime(lookup.created_at):%Y%m%d-%H%M}.pdf"


def render(lookup, request):
    if lookup.kind == "compare":
        return render_comparison(lookup, request)
    locations, assets = geo_data(lookup.sources), {}
    if locations and (image := geo.static_map(locations["punkte"])):
        assets["way-asset:map.png"] = image
        locations["bild"] = True
    html = render_to_string(
        "lookups/report_pdf.html",
        {"lookup": lookup, "generated_at": timezone.now(), "scan": scan_data(lookup.sources),
         "history": history_data(lookup.sources), "geo": locations},
        request=request,
    )
    return HTML(string=html, url_fetcher=BlockingFetcher(assets=assets, allowed_protocols=())).write_pdf()


def render_comparison(lookup, request):
    """Vergleich samt gemeinsamer Karte, danach je verglichener Analyse Bericht und Rohdaten (älteste zuerst)."""
    members = list(lookup.compared.select_related("created_by").order_by("created_at"))
    places, assets = geo.comparison(members), {}
    if places and (image := geo.static_map(places["punkte"])):
        assets["way-asset:map.png"] = image
        places["bild"] = True
    html = render_to_string(
        "lookups/compare_pdf.html",
        {"lookup": lookup, "generated_at": timezone.now(), "members": members, "places": places},
        request=request,
    )
    return HTML(string=html, url_fetcher=BlockingFetcher(assets=assets, allowed_protocols=())).write_pdf()
