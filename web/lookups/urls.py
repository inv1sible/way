from django.urls import path

from . import views

app_name = "lookups"

urlpatterns = [
    path("", views.index, name="index"),
    path("teilen/", views.share, name="share"),
    path("analyse/<int:pk>/", views.detail, name="detail"),
    path("analyse/<int:pk>/status/", views.status, name="status"),
    path("analyse/<int:pk>/erneut/", views.rerun, name="rerun"),
    path("analyse/<int:pk>/pdf/", views.report_pdf, name="pdf"),
    path("manifest.webmanifest", views.manifest, name="manifest"),
    # ohne .js-Endung, damit Reverse-Proxy-Caches für statische Dateien sie nicht zwischenspeichern
    path("service-worker", views.service_worker, name="service_worker"),
]
