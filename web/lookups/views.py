import hashlib
import json
import re
from datetime import date

from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.templatetags.static import static
from django.urls import reverse
from django.utils import timezone
from django.utils import translation
from django.views.decorators.cache import cache_control, never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import historie, ownership, pdf
from .collectors import fritzbox
from .detect import detect, extract, vcard_text
from .models import Lookup, OwnedTarget
from .templatetags.report_tags import fundstellen, history_data, scan_data
from .tasks import run_lookup


def ui_text(german, english):
    return english if (translation.get_language() or "de").startswith("en") else german


def _start(request, kind, query, active=False, active_ports=None, active_timeout=8, active_profile=None,
           enrichment_of=None, scan=False, as_of=None, note=None):
    # Direkter Kontakt zu fremden Zielen nur für Admins: Er geht von der Adresse dieses Servers aus.
    if note is None and request.user.is_authenticated:
        previous = Lookup.objects.filter(created_by=request.user, kind=kind, query=query).exclude(note="").first()
        note = previous.note if previous else ""
    lookup = Lookup.objects.create(
        kind=kind, query=query, created_by=request.user,
        active_probe=bool(active and request.user.is_staff), port_scan=bool(scan and request.user.is_staff),
        active_ports=active_ports or fritzbox.DEFAULT_PORTS, active_timeout=active_timeout,
        active_profile=active_profile or Lookup.ActiveProfile.FRITZBOX, enrichment_of=enrichment_of,
        as_of=as_of, note=note or "",
    )
    transaction.on_commit(lambda: run_lookup.delay(lookup.pk))
    return redirect("lookups:detail", pk=lookup.pk)


def _visible(request):
    """Nutzer sehen nur ihre eigenen Analysen, Admins alle."""
    lookups = Lookup.objects.select_related("created_by")
    return lookups if request.user.is_staff else lookups.filter(created_by=request.user)


def _grouped(request, limit=50):
    """Verlauf: je Abfrage (und Nutzer) nur die neueste Analyse, mit allen Läufen der Gruppe. Gruppiert wird
    in Python, damit auch Analysen ohne Eigentümer (NULL) zusammenfinden."""
    groups = {}
    for pk, kind, query, owner in _visible(request).values_list("pk", "kind", "query", "created_by_id"):
        groups.setdefault((kind, query, owner), []).append(pk)  # neueste zuerst (Sortierung des Modells)
    latest = {pks[0]: pks for pks in groups.values()}
    shown = list(_visible(request).filter(pk__in=list(latest)[:limit]))
    for lookup in shown:
        lookup.runs = latest[lookup.pk]
    # Neueste zuerst, innerhalb derselben (angezeigten) Minute alphabetisch, z. B. bei mehreren gleichzeitig gestarteten
    shown.sort(key=lambda l: l.query.casefold())
    shown.sort(key=lambda l: l.created_at.replace(second=0, microsecond=0), reverse=True)
    return shown, len(groups)


def _index(request, q="", error=None, shared=None):
    lookups, total = _grouped(request)
    return render(
        request,
        "lookups/index.html",
        {"lookups": lookups, "total": total, "q": q, "error": error, "shared": shared,
         "today": timezone.localdate().isoformat()},
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
    try:
        as_of = parse_as_of(request.POST.get("asof", ""))
    except ValueError as exc:
        return _index(request, q=query, error=str(exc))
    scan = request.POST.get("scan") == "on" and request.user.is_staff and kind != "phone"
    if scan and not ownership.is_owned(kind, value):
        return _index(request, q=query, error=ui_text(
            f"„{value}“ ist nicht als eigenes System eingetragen. Der Portscan ist nur für eigene Systeme erlaubt.",
            f"“{value}” is not registered as an owned system. Port scans are allowed only for owned systems.",
        ))
    active = request.POST.get("active") == "on" and request.user.is_staff and kind != "phone"
    active_ports, active_timeout = fritzbox.DEFAULT_PORTS, fritzbox.DEFAULT_TIMEOUT
    if active:
        if not ownership.is_owned(kind, value):
            return _index(request, q=query, error=ui_text(
                "Aktive Prüfungen sind nur für als eigene Systeme eingetragene Ziele erlaubt.",
                "Active checks are allowed only for targets registered as owned systems.",
            ))
        if kind == "ip" and not fritzbox.public_address(value):
            return _index(request, q=query, error=ui_text(
                "Die leichte aktive Prüfung ist nur für öffentlich routbare Ziele erlaubt.",
                "The active-light check is allowed only for publicly routable targets.",
            ))
        try:
            active_ports = fritzbox.parse_ports(request.POST.get("active_ports"))
            active_timeout = fritzbox.parse_timeout(request.POST.get("active_timeout"))
        except ValueError as exc:
            return _index(request, q=query, error=str(exc))
    return _start(request, kind, value, active=active, active_ports=active_ports,
                  active_timeout=active_timeout, scan=scan, as_of=as_of)


@require_POST
def delete(request):
    """Ausgewählte Analysen aus dem Verlauf löschen. Nur sichtbare (eigene, bei Admins alle) und nur
    abgeschlossene: In laufende schreibt der Worker noch."""
    # Ein Eintrag im Verlauf steht für alle Läufe derselben Abfrage: "36,31,30"
    ids = [int(i) for value in request.POST.getlist("ids") for i in value.split(",") if i.isdigit()]
    chosen = _visible(request).filter(pk__in=ids)
    running = chosen.filter(status__in=(Lookup.Status.PENDING, Lookup.Status.COLLECTING, Lookup.Status.ANALYZING))
    skipped = running.count()
    done = chosen.exclude(pk__in=running.values("pk"))
    deleted = done.count()
    done.delete()
    if deleted:
        messages.info(request, ui_text(
            f"{deleted} Analyse gelöscht." if deleted == 1 else f"{deleted} Analysen gelöscht.",
            f"{deleted} analysis deleted." if deleted == 1 else f"{deleted} analyses deleted.",
        ))
    if skipped:
        messages.info(request, ui_text(
            f"{skipped} laufende Analyse(n) nicht gelöscht, bitte nach dem Abschluss erneut versuchen.",
            f"{skipped} running analysis/analyses were not deleted; try again after completion.",
        ))
    return redirect("lookups:index")


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
    error = None if candidate else ui_text(
        "In den geteilten Daten wurde keine Rufnummer, IP-Adresse oder kein Hostname gefunden.",
        "No phone number, IP address, or hostname was found in the shared data.",
    )
    return _index(request, q=candidate or "", error=error, shared=shared[:500])


FRAGMENTS = ("meta", "progress", "error", "report", "scan", "history", "hits", "actions")


def parse_as_of(text):
    """Stichtag aus dem Formular (YYYY-MM-DD); leer = kein Rückblick."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise ValueError(ui_text("Ungültiges Datum für den Stand.", "Invalid reference date.")) from None
    if day > timezone.localdate():
        raise ValueError(ui_text(
            "Der Stand darf nicht in der Zukunft liegen.", "The reference date cannot be in the future."
        ))
    if day < date(2000, 1, 1):
        raise ValueError(ui_text(
            "Der Stand liegt zu weit zurück (frühestens 2000).",
            "The reference date is too far in the past (earliest 2000).",
        ))
    return day


def _rev(lookup):
    """Billige Kennung des Zustands; stimmt sie mit der des Browsers überein, entfällt das Rendern."""
    return f"{lookup.status}:{len(lookup.sources)}:{len(lookup.report_md)}:{lookup.risk}:{len(lookup.error)}:{lookup.model}"


def _enrichment_context(request, lookup):
    """Steuert die Folgeprüfung und erklärt Admins fehlende Voraussetzungen sichtbar.

    Aktive Verbindungen verlassen diesen Server. Deshalb genügt ein Staff-Account nicht: Das
    konkrete Ziel muss vorher als eigenes System hinterlegt sein. Bei Hostnamen braucht die
    spätere DNS/ASN-Bindung zusätzlich mindestens ein erlaubtes Origin-ASN.
    """
    eligible_kind = lookup.kind in {"ip", "host"}
    owned = eligible_kind and ownership.is_owned(lookup.kind, lookup.query)
    host_needs_asn = lookup.kind == "host" and owned and not ownership.allowed_asns(lookup.kind, lookup.query)
    allowed = request.user.is_staff and not lookup.is_running and owned and not host_needs_asn
    return {
        "enrichment_allowed": allowed,
        "enrichment_setup_required": request.user.is_staff and not lookup.is_running and eligible_kind and not allowed,
        "enrichment_requires_asn": host_needs_asn,
        "owned_target_setup_available": request.user.is_staff and not lookup.is_running and eligible_kind,
    }


def _owned_target_suggestion(lookup):
    """Vorbelegung aus dem vorhandenen Analyse-Snapshot, ohne neue externe Anfrage.

    ASN ist die maschinenlesbare Schranke für aktive Hostname-Prüfungen. Provider-Namen bleiben
    Kontext für Menschen: Sie sind nicht stabil genug, um daraus eine Sicherheitsentscheidung zu
    treffen. Die Nutzerin bzw. der Nutzer bestätigt beide Werte vor dem Speichern.
    """
    if lookup.kind not in {"ip", "host"}:
        return None
    addresses, asns, providers, evidence, reverse_dns = [], set(), [], [], ""
    for source in lookup.sources or []:
        name, data = source.get("source", ""), source.get("data") or {}
        if not source.get("ok") or not isinstance(data, dict):
            continue
        if name == "DNS-Auflösung":
            addresses.extend(str(value) for value in data.get("adressen", []) if value)
            evidence.append(name)
        if name == "Reverse DNS":
            reverse_dns = str(data.get("ptr") or "").strip().lower().rstrip(".")
            evidence.append(name)
        if name.startswith("ASN und Netzbetreiber"):
            asns.update(str(value) for value in data.get("asn", []) if value)
            evidence.append(name)
        if name.startswith("ip-api.com"):
            asns.update(re.findall(r"\bAS\d+\b", str(data.get("as") or ""), flags=re.IGNORECASE))
            providers.extend(str(data.get(key)).strip() for key in ("isp", "org", "asname") if data.get(key))
            evidence.append(name)
        if name.startswith("RDAP") and data.get("netzname"):
            providers.append(str(data["netzname"]).strip())
            evidence.append(name)
        if name == "Dynamische Zielbindung (DNS/ASN)":
            for resolved in data.get("resolvedAddresses", []):
                if isinstance(resolved, dict):
                    addresses.append(str(resolved.get("address") or ""))
                    asns.update(str(value) for value in resolved.get("originAsns", []) if value)
            evidence.append(name)
    try:
        normal_asns = sorted(ownership.parse_asns(",".join(asns)))
    except Exception:
        normal_asns = []
    return {
        "value": lookup.query,
        "addresses": sorted({address for address in addresses if address}),
        "asn": ", ".join(normal_asns),
        "provider": " · ".join(dict.fromkeys(value for value in providers if value))[:200],
        "dns_name": reverse_dns,
        "evidence": ", ".join(dict.fromkeys(evidence)),
    }


def _fragments(request, lookup):
    """Teile der Detailseite als HTML samt Hash. Die Seite und der Status-Abruf nutzen dieselben
    Vorlagen; der Browser ersetzt nur Teile, deren Hash sich geändert hat."""
    context = {"lookup": lookup, "hits": fundstellen(lookup.sources), "count": len(lookup.sources),
               "scan": scan_data(lookup.sources), "history": history_data(lookup.sources),
               **_enrichment_context(request, lookup)}

    def part(html):
        return {"html": html, "h": hashlib.sha1(html.encode()).hexdigest()[:12]}

    return {
        "fragments": {name: part(render_to_string(f"lookups/live/{name}.html", context, request=request))
                      for name in FRAGMENTS},
        "sources": [
            {"key": source["source"], **part(render_to_string("lookups/live/source.html", {"s": source}))}
            for source in sorted(lookup.sources, key=lambda item: str(item.get("source", "")).casefold())
        ],
    }


def _other_runs(request, lookup):
    """Weitere Läufe derselben Abfrage desselben Eigentümers, frisch aus der Datenbank (der im Bericht
    gespeicherte Verlauf kann auf inzwischen gelöschte Analysen zeigen). Jeder Lauf trägt seine Änderungen
    gegenüber dem vorigen noch vorhandenen fertigen Lauf (run.changes; None beim ersten)."""
    runs = _visible(request).filter(kind=lookup.kind, query=lookup.query)
    if lookup.created_by_id is None:
        runs = runs.filter(created_by__isnull=True)
    else:
        runs = runs.filter(created_by_id=lookup.created_by_id)
    previous = None
    runs = list(runs.order_by("created_at"))
    for run in runs:
        run.changes = None
        if run.status != Lookup.Status.DONE:
            continue
        if previous is not None:
            run.changes = historie.compare(previous.sources, run.sources)
            if previous.risk and run.risk and previous.risk != run.risk:
                run.changes.insert(0, ("risiko", previous.risk, run.risk))
        previous = run
    return [run for run in reversed(runs) if run.pk != lookup.pk]


def detail(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    return render(request, "lookups/detail.html", {
        "lookup": lookup, "rev": _rev(lookup), "runs": _other_runs(request, lookup),
        "owned_suggestion": _owned_target_suggestion(lookup),
        **_enrichment_context(request, lookup),
        **_fragments(request, lookup),
    })


@never_cache
def status(request, pk):
    """Zwischenstand einer Analyse für die Detailseite (Abruf alle paar Sekunden)."""
    lookup = get_object_or_404(_visible(request), pk=pk)
    rev = _rev(lookup)
    base = {"running": lookup.is_running, "rev": rev}
    if request.GET.get("rev") == rev:
        return JsonResponse({**base, "unchanged": True})
    return JsonResponse({**base, **_fragments(request, lookup)})


def report_pdf(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    if lookup.is_running:
        return redirect("lookups:detail", pk=pk)
    language = request.GET.get("language")
    if language not in {"de", "en"}:
        language = translation.get_language() or "de"
    language = "en" if language.lower().startswith("en") else "de"
    with translation.override(language):
        content = pdf.render(lookup, request)
        filename = pdf.filename(lookup, language)
    response = HttpResponse(content, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["Content-Language"] = language
    return response


@require_POST
def note(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    lookup.note = " ".join(request.POST.get("note", "").split())[:200]
    lookup.save(update_fields=["note"])  # nur dieses Feld: Der Worker schreibt evtl. gleichzeitig in die anderen
    return redirect("lookups:detail", pk=pk)


@require_POST
def own_target(request, pk):
    """Speichert das feste, aus der Detailansicht stammende Ziel als eigenes System.

    Der Client darf Provider und ASNs korrigieren, aber weder IP noch Hostname ersetzen. So wird
    aus einem Detaildialog kein Weg, beliebige Ziele als eigene Systeme zu hinterlegen.
    """
    lookup = get_object_or_404(_visible(request), pk=pk)
    if not request.user.is_staff:
        raise PermissionDenied
    if lookup.kind not in {"ip", "host"}:
        raise PermissionDenied
    if request.POST.get("ownership_confirmation") != "confirmed":
        messages.error(request, ui_text(
            "Bitte bestätige, dass dieses System dir gehört oder du es ausdrücklich verwalten darfst.",
            "Confirm that you own this system or are explicitly authorized to administer it.",
        ))
        return redirect("lookups:detail", pk=lookup.pk)
    try:
        _kind, value = ownership.parse(lookup.query)
        asn = ", ".join(sorted(ownership.parse_asns(request.POST.get("asn", ""))))
        provider = " ".join(request.POST.get("provider", "").split())[:200]
        dns_name = request.POST.get("dns_name", "") if lookup.kind == "ip" else ""
        target, created = OwnedTarget.objects.get_or_create(
            value=value,
            defaults={"asn": asn, "provider": provider, "dns_name": dns_name,
                      "note": f"Aus Analyse {lookup.pk} übernommen."},
        )
        if not created:
            target.asn, target.provider, target.dns_name = asn, provider, dns_name
            target.save(update_fields=["asn", "provider", "dns_name"])
    except Exception as exc:
        messages.error(request, ui_text(f"Eigenes System wurde nicht gespeichert: {exc}",
                                        f"Owned system was not saved: {exc}"))
        return redirect("lookups:detail", pk=lookup.pk)
    messages.success(request, ui_text(
        f"„{target.value}“ ist als eigenes System gespeichert.",
        f"“{target.value}” is saved as an owned system.",
    ))
    return redirect("lookups:detail", pk=lookup.pk)


@require_POST
def rerun(request, pk):
    lookup = get_object_or_404(_visible(request), pk=pk)
    return _start(
        request, lookup.kind, lookup.query, active=lookup.active_probe,
        active_ports=lookup.active_ports, active_timeout=lookup.active_timeout,
        active_profile=lookup.active_profile,
        scan=lookup.port_scan, as_of=lookup.as_of, note=lookup.note,
    )


@require_POST
def enrich(request, pk):
    """Explizite, begrenzte Folgeprüfung; der passive Ursprungslauf bleibt unverändert."""
    lookup = get_object_or_404(_visible(request), pk=pk)
    if not request.user.is_staff:
        raise PermissionDenied
    if lookup.is_running:
        return redirect("lookups:detail", pk=lookup.pk)
    if lookup.kind == "phone" or not ownership.is_owned(lookup.kind, lookup.query):
        messages.error(request, ui_text(
            "Aktive Anreicherung ist nur für als eigene Systeme eingetragene IP-Adressen oder Hostnamen erlaubt.",
            "Active enrichment is allowed only for IP addresses or hostnames registered as owned systems.",
        ))
        return redirect("lookups:detail", pk=lookup.pk)
    if request.POST.get("authorization") != "confirmed":
        messages.error(request, ui_text(
            "Bitte bestätige die Berechtigung für die aktive Prüfung.",
            "Confirm authorization for the active check.",
        ))
        return redirect("lookups:detail", pk=lookup.pk)
    profile = request.POST.get("profile", Lookup.ActiveProfile.GENERIC_ROUTER)
    if profile not in {Lookup.ActiveProfile.GENERIC_ROUTER, Lookup.ActiveProfile.FRITZBOX, Lookup.ActiveProfile.SPEEDPORT}:
        messages.error(request, ui_text("Ungültiges Prüfprofil.", "Invalid probe profile."))
        return redirect("lookups:detail", pk=lookup.pk)
    default_ports = {
        Lookup.ActiveProfile.GENERIC_ROUTER: [443],
        Lookup.ActiveProfile.FRITZBOX: fritzbox.DEFAULT_PORTS,
        Lookup.ActiveProfile.SPEEDPORT: [80, 443],
    }[profile]
    try:
        ports = fritzbox.parse_ports(request.POST.get("active_ports"), default=default_ports)
        timeout = fritzbox.parse_timeout(request.POST.get("active_timeout"))
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("lookups:detail", pk=lookup.pk)
    return _start(
        request, lookup.kind, lookup.query, active=True, active_ports=ports, active_timeout=timeout,
        active_profile=profile, enrichment_of=lookup, as_of=lookup.as_of, note=lookup.note,
    )


@login_not_required
@never_cache
def manifest(request):
    language = "en" if (translation.get_language() or "de").startswith("en") else "de"
    return JsonResponse(
        {
            "name": "Who Are You",
            "short_name": "Who Are You",
            "description": ui_text(
                "Rufnummern, IP-Adressen und Hostnamen analysieren",
                "Analyze phone numbers, IP addresses, and hostnames",
            ),
            "lang": language,
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
const OFFLINE = "__OFFLINE__";

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
    offline = (
        '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<title>Offline</title><body style="font-family:system-ui;padding:24px">'
        '<h1>Offline</h1><p>Who Are You is currently unavailable.</p>'
        if (translation.get_language() or "de").startswith("en") else
        '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<title>Offline</title><body style="font-family:system-ui;padding:24px">'
        '<h1>Keine Verbindung</h1><p>Who Are You ist gerade nicht erreichbar.</p>'
    )
    return HttpResponse(SERVICE_WORKER.replace('"__OFFLINE__"', json.dumps(offline)), content_type="application/javascript")
