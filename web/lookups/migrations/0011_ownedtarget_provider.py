# Generated manually for the owned-system setup dialog.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0010_lookup_speedport_profile"),
    ]

    operations = [
        migrations.AddField(
            model_name="ownedtarget",
            name="provider",
            field=models.CharField(
                blank=True,
                help_text="Nur dokumentarisch: aus der Analyse übernommener Provider oder Netzname. Die aktive Prüfung vergleicht technisch AS-Nummern, nicht diesen Freitext.",
                max_length=200,
                verbose_name="Provider/Netzbetreiber",
            ),
        ),
    ]
