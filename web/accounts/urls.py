from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("einladungen/", views.invitations, name="invitations"),
    path("einladungen/<int:pk>/widerrufen/", views.revoke, name="revoke"),
    path("einladung/<str:token>/", views.register, name="register"),
    path("bestaetigen/<str:token>/", views.confirm, name="confirm"),
]
