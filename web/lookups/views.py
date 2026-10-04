from django.contrib.auth.decorators import login_not_required
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.templatetags.static import static
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from .detect import detect, extract
from .models import Lookup
from .tasks import run_lookup


def _start(request, kind, query):
    lookup = Lookup.objects.create(kind=kind, query=query, created_by=request.user)
    transaction.on_commit(lambda: run_lookup.delay(lookup.pk))
    return redirect("lookups:detail", pk=lookup.pk)


def _visible(request):
    """Nutzer sehen nur ihre eigenen Analysen, Admins alle."""
    lookups = Lookup.objects.select_related("created_by")
    return lookups if request.user.is_staff else lookups.filter(created_by=request.user)


def _index(request, q="", error=None, shared=None):
    return render(
        request,
        "lookups/index.html",
        {"lookups": _visible(request)[:50], "q": q, "error": error, "shared": shared},
        status=400 if error and request.method == "POST" else 200,
    )


def index(request):
    if request.method != "POST":
        return _index(request, q=request.GET.get("q", ""))
    query = request.POST.get("q", "")
    try:
        kind, value = detect(query)
    except ValueError as exc:
        return _index(request, q=query, error=str(exc))
    return _start(request, kind, value)


def share(request):
    """Ziel des PWA-Teilen-Menüs: füllt das Formular mit dem gefundenen Wert vor.

    Bewusst ohne automatischen Start, damit fremde Links keine Analysen auslösen können.
    """
    shared = " ".join(v for v in (request.GET.get(k, "").strip() for k in ("text", "url", "title")) if v)
    candidate = extract(shared)
    error = None if candidate else "In den geteilten Daten wurde keine Rufnummer, IP-Adresse oder kein Hostname gefunden."
    return _index(request, q=candidate or "", error=error, shared=shared[:500])


def detail(request, pk):
    return render(request, "lookups/detail.html", {"lookup": get_object_or_404(_visible(request), pk=pk)})


@require_POST
def rerun(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    return _start(request, lookup.kind, lookup.query)


@login_not_required
@cache_control(max_age=3600)
def manifest(request):
    return JsonResponse(
        {
            "name": "OSINT-Agent",
            "short_name": "OSINT",
            "description": "Rufnummern, IP-Adressen und Hostnamen analysieren",
            "lang": "de",
            "id": "/",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "background_color": "#121418",
            "theme_color": "#2557d6",
            "icons": [
                {"src": static("lookups/icons/icon-192.png"), "sizes": "192x192", "type": "image/png"},
                {"src": static("lookups/icons/icon-512.png"), "sizes": "512x512", "type": "image/png"},
                {"src": static("lookups/icons/maskable-512.png"), "sizes": "512x512", "type": "image/png",
                 "purpose": "maskable"},
            ],
            "share_target": {
                "action": reverse("lookups:share"),
                "method": "GET",
                "params": {"title": "title", "text": "text", "url": "url"},
            },
        },
        content_type="application/manifest+json",
        json_dumps_params={"ensure_ascii": False},
    )


SERVICE_WORKER = """
const OFFLINE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
  + '<title>Offline</title><body style="font-family:system-ui;padding:24px">'
  + '<h1>Keine Verbindung</h1><p>Der OSINT-Agent ist gerade nicht erreichbar.</p>';

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  if (event.request.mode !== "navigate") return;
  event.respondWith(
    fetch(event.request).catch(
      () => new Response(OFFLINE, { headers: { "Content-Type": "text/html; charset=utf-8" } })
    )
  );
});
"""


@login_not_required
@cache_control(no_cache=True)
def service_worker(request):
    return HttpResponse(SERVICE_WORKER, content_type="application/javascript")
