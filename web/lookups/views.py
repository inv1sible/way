from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .detect import detect
from .models import Lookup
from .tasks import run_lookup


def _start(request, kind, query):
    lookup = Lookup.objects.create(kind=kind, query=query, created_by=request.user)
    transaction.on_commit(lambda: run_lookup.delay(lookup.pk))
    return redirect("lookups:detail", pk=lookup.pk)


def index(request):
    error = None
    query = request.POST.get("q", "") if request.method == "POST" else request.GET.get("q", "")
    if request.method == "POST":
        try:
            kind, value = detect(query)
        except ValueError as exc:
            error = str(exc)
        else:
            return _start(request, kind, value)
    return render(
        request,
        "lookups/index.html",
        {"lookups": Lookup.objects.all()[:50], "q": query, "error": error},
        status=400 if error else 200,
    )


def detail(request, pk):
    return render(request, "lookups/detail.html", {"lookup": get_object_or_404(Lookup, pk=pk)})


@require_POST
def rerun(request, pk):
    lookup = get_object_or_404(Lookup, pk=pk)
    return _start(request, lookup.kind, lookup.query)
