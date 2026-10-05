from django.contrib import admin

from .models import Lookup, OwnedTarget


@admin.register(Lookup)
class LookupAdmin(admin.ModelAdmin):
    list_display = ("query", "kind", "risk", "status", "created_at", "created_by")
    list_filter = ("kind", "risk", "status")
    search_fields = ("query",)
    readonly_fields = ("created_at", "finished_at")


@admin.register(OwnedTarget)
class OwnedTargetAdmin(admin.ModelAdmin):
    list_display = ("value", "asn", "note", "created_at")
    search_fields = ("value", "note")
