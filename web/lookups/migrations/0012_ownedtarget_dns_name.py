# Generated manually for optional IP-to-DNS target binding.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0011_ownedtarget_provider"),
    ]

    operations = [
        migrations.AddField(
            model_name="ownedtarget",
            name="dns_name",
            field=models.CharField(
                blank=True,
                help_text="Optionaler, ausdrücklich bestätigter Hostname für eine IP-Adresse. Bei aktiven IP-Prüfungen muss er weiterhin auf die geprüfte IP auflösen.",
                max_length=255,
                verbose_name="DNS-Name",
            ),
        ),
    ]
