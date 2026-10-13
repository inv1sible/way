from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0015_lookup_email_public_web"),
    ]

    operations = [
        migrations.AlterField(
            model_name="lookup",
            name="kind",
            field=models.CharField(
                choices=[
                    ("email", "E-Mail-Adresse"),
                    ("phone", "Rufnummer"),
                    ("ip", "IP-Adresse"),
                    ("host", "Hostname"),
                ],
                max_length=10,
                verbose_name="Typ",
            ),
        ),
    ]
