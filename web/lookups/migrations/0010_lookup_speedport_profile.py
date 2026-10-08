# Generated manually for the opt-in, read-only Speedport fingerprint profile.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0009_lookup_active_profile_and_enrichment"),
    ]

    operations = [
        migrations.AlterField(
            model_name="lookup",
            name="active_profile",
            field=models.CharField(
                choices=[("fritzbox", "FRITZ!Box"), ("generic-router", "Generischer Router"),
                         ("speedport", "Speedport")],
                default="fritzbox", help_text="Ausdrücklich ausgewähltes, nicht destruktives aktives Prüfprofil.",
                max_length=20, verbose_name="aktives Profil",
            ),
        ),
    ]
