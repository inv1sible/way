from django.contrib.auth.decorators import login_not_required
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.templatetags.static import static
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import pdf
from .detect import detect, extract, vcard_text
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


@csrf_exempt  # verändert nichts, füllt nur das Formular vor; POST kommt vom Teilen-Menü ohne Token
def share(request):
    """Ziel des PWA-Teilen-Menüs: füllt das Formular mit dem gefundenen Wert vor.

    Normalerweise wandelt der Service Worker das geteilte POST in ein GET um; der POST-Zweig
    greift nur, wenn er (noch) nicht aktiv ist. Bewusst ohne automatischen Start, damit fremde
    Links keine Analysen auslösen können.
    """
    params = request.POST if request.method == "POST" else request.GET
    parts = [params.get(k, "").strip() for k in ("text", "url", "title")]
    for upload in request.FILES.getlist("files")[:5]:
        parts.append(vcard_text(upload.read(100_000).decode("utf-8", "replace")))
    shared = " ".join(p for p in parts if p)
    candidate = extract(shared)
    error = None if candidate else "In den geteilten Daten wurde keine Rufnummer, IP-Adresse oder kein Hostname gefunden."
    return _index(request, q=candidate or "", error=error, shared=shared[:500])


def detail(request, pk):
    return render(request, "lookups/detail.html", {"lookup": get_object_or_404(_visible(request), pk=pk)})


def report_pdf(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    if lookup.is_running:
        return redirect("lookups:detail", pk=pk)
    response = HttpResponse(pdf.render(lookup, request), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{pdf.filename(lookup)}"'
    return response


@require_POST
def rerun(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    return _start(request, lookup.kind, lookup.query)


@login_not_required
@cache_control(max_age=3600)
def manifest(request):
    return JsonResponse(
        {
            "name": "Who Are You",
            "short_name": "Who Are You",
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
            # POST + multipart, damit auch Visitenkarten (.vcf) aus Telefon- und Kontakte-Apps
            # angenommen werden; der Service Worker wandelt das in einen GET auf /teilen/ um.
            "share_target": {
                "action": reverse("lookups:share"),
                "method": "POST",
                "enctype": "multipart/form-data",
                "params": {
                    "title": "title",
                    "text": "text",
                    "url": "url",
                    "files": [{"name": "files", "accept": ["text/vcard", "text/x-vcard", ".vcf", "text/plain"]}],
                },
            },
        },
        content_type="application/manifest+json",
        json_dumps_params={"ensure_ascii": False},
    )


# Raw-String: die regulären Ausdrücke im JavaScript enthalten Backslashes.
SERVICE_WORKER = r"""
const OFFLINE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
  + '<title>Offline</title><body style="font-family:system-ui;padding:24px">'
  + '<h1>Keine Verbindung</h1><p>Who Are You ist gerade nicht erreichbar.</p>';

// Rufnummern aus einer Visitenkarte (vCard) ziehen; andere Dateien als Text übernehmen.
function vcardText(text) {
  if (!/BEGIN:VCARD/i.test(text)) return text.slice(0, 2000);
  return text.replace(/\r?\n[ \t]/g, "").split(/\r?\n/)
    .filter((line) => /^(item\d+\.)?TEL[;:]/i.test(line))
    .map((line) => line.slice(line.indexOf(":") + 1).replace(/^tel:/i, ""))
    .join(" ");
}

async function shareRedirect(request) {
  const form = await request.formData();
  const parts = ["text", "url", "title"].map((key) => form.get(key)).filter(Boolean);
  for (const file of form.getAll("files")) {
    if (typeof file !== "string") parts.push(vcardText(await file.text()));
  }
  const target = new URL("/teilen/", self.location.origin);
  target.searchParams.set("text", parts.join(" ").slice(0, 2000));
  return Response.redirect(target.href, 303);
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method === "POST" && url.pathname === "/teilen/") {
    event.respondWith(shareRedirect(event.request));
    return;
  }
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
