"""Do not retain derived telephone-search hypotheses in historic analyses."""

import re

from django.db import migrations


ALLOWED_EXTENSION_LENGTHS = {4, 5, 6}


def _digits(value):
    return re.sub(r"\D", "", str(value or ""))


def scrub_phone_query_hypotheses(apps, schema_editor):
    Lookup = apps.get_model("lookups", "Lookup")
    for lookup in Lookup.objects.exclude(sources=[]).iterator():
        sources = lookup.sources or []
        changed = False
        for source in sources:
            data = source.get("data")
            if not isinstance(data, dict):
                continue
            name = source.get("source")
            if name == "Websuche (SearXNG)" and data.pop("abfragevarianten", None) is not None:
                changed = True
            if name in {"Websuche: mögliche Zentralnummern", "Stammnummernabgleich (Websuche)"}:
                if data.pop("kandidaten", None) is not None:
                    changed = True
                # Die alte Evidenz wurde mit einer breiteren Kandidatenbildung erzeugt.
                # Sie wird nicht weiter als Beleg angezeigt; die Fundstellen bleiben erhalten.
                if data.pop("evidenz", None) is not None:
                    changed = True
                data["hinweis"] = "Historischer Stammnummernabgleich ohne gespeicherte Suchhypothesen; für eine aktuelle Einordnung bitte erneut analysieren."
                changed = True
            if name == "Stammnummern-Zuordnung":
                evidence = data.get("belegteOrganisationszuordnung") or []
                valid = [
                    item for item in evidence
                    if len(_digits(item.get("moeglicheDurchwahl"))) in ALLOWED_EXTENSION_LENGTHS
                ]
                if valid != evidence:
                    changed = True
                data["belegteOrganisationszuordnung"] = valid
                stem = valid[0] if valid else None
                data["vermuteteStammnummer"] = (
                    {key: stem[key] for key in (
                        "stammnummer", "veroeffentlichteNummer", "organisation", "sourceUrl", "fundstelle", "abgerufenAm"
                    )}
                    if stem else None
                )
                data["moeglicheDurchwahl"] = stem.get("moeglicheDurchwahl") if stem else None
                changed = True
        if changed:
            lookup.sources = sources
            lookup.save(update_fields=["sources"])


class Migration(migrations.Migration):

    dependencies = [
        ("lookups", "0012_ownedtarget_dns_name"),
    ]

    operations = [
        migrations.RunPython(scrub_phone_query_hypotheses, migrations.RunPython.noop),
    ]
