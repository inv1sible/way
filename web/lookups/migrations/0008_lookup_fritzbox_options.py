# Generated manually for the defensive FRITZ!Box fingerprint options.

import lookups.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0007_lookup_note"),
    ]

    operations = [
        migrations.AddField(
            model_name="lookup",
            name="active_ports",
            field=models.JSONField(
                default=lookups.models.default_active_ports,
                help_text="Höchstens vier explizit freigegebene Ports; 80/8080 per HTTP, alle anderen per HTTPS.",
                verbose_name="aktive Web-Ports",
            ),
        ),
        migrations.AddField(
            model_name="lookup",
            name="active_timeout",
            field=models.PositiveSmallIntegerField(
                default=8,
                help_text="Timeout je aktiver Anfrage in Sekunden (2 bis 20).",
                verbose_name="aktiver Timeout",
            ),
        ),
        migrations.AlterField(
            model_name="lookup",
            name="active_probe",
            field=models.BooleanField(
                default=False,
                help_text="Berechtigung bestätigt; Ziel direkt für den FRITZ!Box-Fingerprint kontaktieren.",
                verbose_name="leicht aktiv",
            ),
        ),
    ]
