"""Lädt die freien DB-IP-Lite-Datenbanken (City und ASN, MaxMind-Format) in OSINT_GEOIP_DIR."""

import datetime
import gzip
import os
import shutil
import tempfile
import time
from pathlib import Path

import httpx
import maxminddb
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
KINDS = ("city", "asn")
MAX_AGE_DAYS = 30


def _months(today):
    # DB-IP veröffentlicht zu Monatsbeginn; bis dahin gilt die Datei des Vormonats.
    previous = today.replace(day=1) - datetime.timedelta(days=1)
    return [f"{today:%Y-%m}", f"{previous:%Y-%m}"]


class Command(BaseCommand):
    help = "Lädt DB-IP Lite (City/ASN) für die lokale IP-Analyse herunter, wenn sie fehlt oder älter als 30 Tage ist."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true", help="auch eine aktuelle Datei neu laden")

    def handle(self, *args, force=False, **options):
        folder = Path(settings.OSINT_GEOIP_DIR)
        folder.mkdir(parents=True, exist_ok=True)
        for kind in KINDS:
            target = folder / f"dbip-{kind}-lite.mmdb"
            if not force and target.is_file() and time.time() - target.stat().st_mtime < MAX_AGE_DAYS * 86400:
                self.stdout.write(f"{target.name} ist aktuell")
                continue
            self._download(kind, target)

    def _download(self, kind, target):
        with httpx.Client(timeout=httpx.Timeout(300, connect=15), follow_redirects=True) as client:
            for month in _months(datetime.date.today()):
                url = URL.format(kind=kind, month=month)
                with client.stream("GET", url) as response:
                    if response.status_code == 404:
                        continue
                    response.raise_for_status()
                    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".part")
                    try:
                        with os.fdopen(fd, "wb") as out:
                            for chunk in response.iter_bytes():
                                out.write(chunk)
                        unpacked = tmp + ".mmdb"
                        with gzip.open(tmp, "rb") as src, open(unpacked, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        maxminddb.open_database(unpacked).close()  # beschädigte Downloads nicht übernehmen
                        os.replace(unpacked, target)
                    finally:
                        for leftover in (tmp, tmp + ".mmdb"):
                            if os.path.exists(leftover):
                                os.remove(leftover)
                self.stdout.write(f"{target.name} geladen ({month})")
                return
        raise CommandError(f"Keine DB-IP-Datei für {kind} gefunden")
