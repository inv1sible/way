from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0016_alter_lookup_kind"),
    ]

    operations = [
        migrations.AddField(
            model_name="lookup",
            name="phone_public_web",
            field=models.BooleanField(
                default=False,
                help_text="Ausdrücklich bestätigte, begrenzte Suche nach der Rufnummer in öffentlichen Web-Suchergebnissen.",
                verbose_name="Öffentliche Rufnummern-Referenzen",
            ),
        ),
    ]
