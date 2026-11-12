"""Lokale GeoIP-Datenbanken im MaxMind-Format (DB-IP Lite oder MaxMind GeoLite2), ohne Netzwerkzugriff."""

import datetime
import ipaddress
from pathlib import Path

import maxminddb
from django.conf import settings

SOURCE = "Lokale GeoIP-Datenbank"
# Erste vorhandene Datei gewinnt: eine selbst abgelegte GeoLite2-Datei vor der automatisch geladenen DB-IP-Datei.
CITY_FILES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
ASN_FILES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")
ATTRIBUTION = {
    "GeoLite2": "Enthält GeoLite2-Daten von MaxMind, https://www.maxmind.com",
    "dbip": "IP Geolocation by DB-IP, https://db-ip.com (CC BY 4.0)",
}


def _find(names):
    folder = Path(settings.OSINT_GEOIP_DIR)
    return next((folder / name for name in names if (folder / name).is_file()), None)


def available():
    return bool(_find(CITY_FILES) or _find(ASN_FILES))


def _name(names):
    return (names or {}).get("de") or (names or {}).get("en")


def _read(path, ip):
    with maxminddb.open_database(str(path)) as reader:
        record, prefix = reader.get_with_prefix_len(ip)
        built = datetime.datetime.fromtimestamp(reader.metadata().build_epoch, datetime.UTC).date().isoformat()
    info = {"datei": path.name, "stand": built, "lizenz": ATTRIBUTION["GeoLite2" if "GeoLite2" in path.name else "dbip"]}
    return record or {}, str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)), info


def lookup(ip):
    city_path, asn_path = _find(CITY_FILES), _find(ASN_FILES)
    if not city_path and not asn_path:
        raise RuntimeError(f"Keine GeoIP-Datenbank in {settings.OSINT_GEOIP_DIR} (python manage.py update_geoip)")
    result, databases = {}, []
    if city_path:
        record, network, info = _read(city_path, ip)
        databases.append(info)
        location = record.get("location") or {}
        subdivisions = record.get("subdivisions") or [{}]
        result.update({
            "land": _name((record.get("country") or {}).get("names")),
            "land_code": (record.get("country") or {}).get("iso_code"),
            "region": _name(subdivisions[0].get("names")),
            "ort": _name((record.get("city") or {}).get("names")),
            "koordinaten": [location["latitude"], location["longitude"]] if "latitude" in location else None,
            # Nur GeoLite2 meldet einen Radius; bei DB-IP schätzt die Karte ihn nach Detailstufe.
            "genauigkeit_km": location.get("accuracy_radius"),
            "netz_geo": network if record else None,
        })
    if asn_path:
        record, network, info = _read(asn_path, ip)
        databases.append(info)
        number = record.get("autonomous_system_number")
        result.update({
            "asn": f"AS{number}" if number else None,
            "as_organisation": record.get("autonomous_system_organization"),
            "netz_asn": network if record else None,
        })
    result = {key: value for key, value in result.items() if value}
    result["hinweis"] = ("Ungefährer Standort des Netzbereichs aus einer lokalen Datenbank; "
                         "kein Hinweis auf Anschlussinhaber oder Gerät.") if result else "Adresse nicht in der Datenbank."
    result["datenbanken"] = databases
    return result
