"""Remove historic analyses whose generated report predates bilingual output."""

from django.db import migrations
from django.db.models import Q


def delete_monolingual_reports(apps, schema_editor):
    Lookup = apps.get_model("lookups", "Lookup")
    bilingual = Q(report_md__contains="# Deutsch") & Q(report_md__contains="# English")
    Lookup.objects.exclude(report_md="").exclude(bilingual).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0013_scrub_phone_query_hypotheses"),
    ]

    operations = [
        migrations.RunPython(delete_monolingual_reports, migrations.RunPython.noop),
    ]
