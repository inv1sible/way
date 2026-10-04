from django.urls import path

from . import views

app_name = "lookups"

urlpatterns = [
    path("", views.index, name="index"),
    path("teilen/", views.share, name="share"),
    path("analyse/<int:pk>/", views.detail, name="detail"),
    path("analyse/<int:pk>/erneut/", views.rerun, name="rerun"),
    path("manifest.webmanifest", views.manifest, name="manifest"),
    path("sw.js", views.service_worker, name="service_worker"),
]
