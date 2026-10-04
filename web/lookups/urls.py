from django.urls import path

from . import views

app_name = "lookups"

urlpatterns = [
    path("", views.index, name="index"),
    path("analyse/<int:pk>/", views.detail, name="detail"),
    path("analyse/<int:pk>/erneut/", views.rerun, name="rerun"),
]
