"""Lädt GeoLite2 (mit MaxMind-Account) oder sonst die freien DB-IP-Lite-Datenbanken (City und ASN) in OSINT_GEOIP_DIR."""

import datetime
import gzip
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

import httpx
import maxminddb
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
MAXMIND_URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
EDITIONS = {"city": "GeoLite2-City", "asn": "GeoLite2-ASN"}
KINDS = ("city", "asn")
MAX_AGE_DAYS = 30


def _months(today):
    # DB-IP veröffentlicht zu Monatsbeginn; bis dahin gilt die Datei des Vormonats.
    previous = today.replace(day=1) - datetime.timedelta(days=1)
    return [f"{today:%Y-%m}", f"{previous:%Y-%m}"]


class Command(BaseCommand):
    help = ("Lädt GeoLite2 (MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY) oder DB-IP Lite (City/ASN) für die lokale "
            "IP-Analyse herunter, wenn die Datei fehlt oder älter als 30 Tage ist.")

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true", help="auch eine aktuelle Datei neu laden")

    def handle(self, *args, force=False, **options):
        folder = Path(settings.OSINT_GEOIP_DIR)
        folder.mkdir(parents=True, exist_ok=True)
        maxmind = bool(settings.OSINT_MAXMIND_ACCOUNT_ID and settings.OSINT_MAXMIND_LICENSE_KEY)
        for kind in KINDS:
            # GeoLite2-Dateien haben in geoip.py Vorrang vor DB-IP; ohne Account bleibt es bei DB-IP.
            target = folder / (f"{EDITIONS[kind]}.mmdb" if maxmind else f"dbip-{kind}-lite.mmdb")
            if not force and target.is_file() and time.time() - target.stat().st_mtime < MAX_AGE_DAYS * 86400:
                self.stdout.write(f"{target.name} ist aktuell")
                continue
            if maxmind:
                self._download_maxmind(EDITIONS[kind], target)
            else:
                self._download(kind, target)

    def _download_maxmind(self, edition, target):
        auth = (settings.OSINT_MAXMIND_ACCOUNT_ID, settings.OSINT_MAXMIND_LICENSE_KEY)
        fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".part")
        unpacked = tmp + ".mmdb"
        try:
            # Der Download leitet auf einen Speicher-Link um; httpx sendet die Zugangsdaten dorthin nicht mit.
            with os.fdopen(fd, "wb") as out, \
                    httpx.Client(timeout=httpx.Timeout(300, connect=15), follow_redirects=True) as client, \
                    client.stream("GET", MAXMIND_URL.format(edition=edition), auth=auth) as response:
                if response.status_code in (401, 403):
                    raise CommandError("MaxMind hat Account-ID oder Lizenzschlüssel abgelehnt")
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    out.write(chunk)
            with tarfile.open(tmp, "r:gz") as archive:
                member = next((m for m in archive.getmembers() if m.isfile() and m.name.endswith(f"/{edition}.mmdb")), None)
                if member is None:
                    raise CommandError(f"{edition}.mmdb fehlt im Archiv")
                with archive.extractfile(member) as src, open(unpacked, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            maxminddb.open_database(unpacked).close()
            os.replace(unpacked, target)
        finally:
            for leftover in (tmp, unpacked):
                if os.path.exists(leftover):
                    os.remove(leftover)
        self.stdout.write(f"{target.name} geladen (MaxMind)")

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
