from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0014_delete_monolingual_reports"),
    ]

    operations = [
        migrations.AddField(
            model_name="lookup",
            name="email_public_web",
            field=models.BooleanField(
                default=False,
                help_text="Ausdrücklich bestätigte, begrenzte Suche nach der exakten E-Mail-Adresse in öffentlichen Web-Suchergebnissen.",
                verbose_name="Öffentliche E-Mail-Referenzen",
            ),
        ),
    ]
