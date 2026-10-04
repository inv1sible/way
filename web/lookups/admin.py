from django.contrib import admin

from .models import Lookup


@admin.register(Lookup)
class LookupAdmin(admin.ModelAdmin):
    list_display = ("query", "kind", "risk", "status", "created_at", "created_by")
    list_filter = ("kind", "risk", "status")
    search_fields = ("query",)
    readonly_fields = ("created_at", "finished_at")
