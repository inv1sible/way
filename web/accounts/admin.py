from django.contrib import admin

from .models import AllowedDomain, Invitation


@admin.register(AllowedDomain)
class AllowedDomainAdmin(admin.ModelAdmin):
    list_display = ("domain",)
    search_fields = ("domain",)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("email", "status", "created_by", "created_at", "expires_at", "used_at", "user")
    search_fields = ("email",)
    readonly_fields = ("email", "created_by", "created_at", "used_at", "user")

    def has_add_permission(self, request):
        return False  # Einladungen entstehen über /einladungen/, damit Link und QR-Code angezeigt werden
