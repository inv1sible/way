"""Standorte aus den Rohdaten: Punkte je Quelle mit Genauigkeit, unabhängig vom KI-Bericht.

Die Punkte entstehen deterministisch aus den gespeicherten Quellen. Meldet eine Quelle einen
Genauigkeitsradius, wird er übernommen; sonst wird er nach Detailstufe (Stadt, Region, Land) geschätzt.
"""

import io
import logging
import math

import httpx
from django.core.cache import cache

from .collectors import USER_AGENT

log = logging.getLogger(__name__)

# Geschätzter Radius, wenn die Quelle keinen nennt: IP-Geolokalisierung ist bestenfalls auf Stadtebene genau.
ESTIMATE_KM = {"stadt": 25, "region": 100, "land": 500}
COLORS = ("#2557d6", "#d63a25", "#1f9d55", "#c27c0e", "#8e44ad", "#0e8a99", "#c2185b")
TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
TILE_CACHE_SECONDS = 7 * 24 * 3600
ATTRIBUTION = "© OpenStreetMap contributors"


def _number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _coords(lat, lon):
    lat, lon = _number(lat), _number(lon)
    if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    return lat, lon


def _extract(name, data):
    """(lat, lon, ort, region, land, radius_km) einer Quelle oder None."""
    if name == "Lokale GeoIP-Datenbank":
        lat, lon = (data.get("koordinaten") or [None, None])[:2]
        return lat, lon, data.get("ort"), data.get("region"), data.get("land"), data.get("genauigkeit_km")
    if name.startswith("ip-api.com"):
        return data.get("lat"), data.get("lon"), data.get("city"), data.get("regionName"), data.get("country"), None
    if name.startswith(("Shodan Host API", "Censys", "Netlas")):
        position = data.get("koordinaten") or [None, None]
        return position[0], position[1], data.get("stadt"), data.get("region"), data.get("land"), None
    return None


def locations(sources):
    """Alle Standortangaben der erfolgreichen Quellen, nummeriert und eingefärbt für Karte und Legende."""
    points = []
    for source in sources or []:
        name, data = source.get("source", ""), source.get("data")
        if not source.get("ok") or not isinstance(data, dict) or not (found := _extract(name, data)):
            continue
        lat, lon, city, region, country, radius = found
        if not (position := _coords(lat, lon)):
            continue
        level = "stadt" if city else "region" if region else "land"
        radius = _number(radius)
        index = len(points)
        points.append({
            "nr": index + 1, "farbe": COLORS[index % len(COLORS)], "quelle": name,
            "lat": round(position[0], 5), "lon": round(position[1], 5),
            "ort": ", ".join(str(part) for part in (city, region, country) if part) or None,
            "genauigkeit_km": radius if radius and radius > 0 else ESTIMATE_KM[level],
            "geschaetzt": not (radius and radius > 0), "stufe": level,
            "osm": f"https://www.openstreetmap.org/?mlat={position[0]:.5f}&mlon={position[1]:.5f}#map=11/{position[0]:.5f}/{position[1]:.5f}",
        })
    return points


def distance_km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def summary(sources):
    """Standorte samt größtem Abstand zwischen den Angaben; None ohne Koordinaten."""
    points = locations(sources)
    if not points:
        return None
    spread = max((distance_km(a, b) for a in points for b in points), default=0)
    return {"punkte": points, "max_abstand_km": round(spread)}


# --- Statisches Kartenbild für das PDF (OSM-Kacheln, im Server zusammengesetzt) ---

def _world(lat, lon, zoom):
    scale = 256 * 2 ** zoom
    sin = math.sin(math.radians(max(min(lat, 85.0511), -85.0511)))
    return (lon + 180) / 360 * scale, (0.5 - math.log((1 + sin) / (1 - sin)) / (4 * math.pi)) * scale


def _radius_px(point, zoom):
    meters_per_px = 156543.03392 * math.cos(math.radians(point["lat"])) / 2 ** zoom
    return point["genauigkeit_km"] * 1000 / meters_per_px


def _fit(points, width, height, margin=30):
    """Größter Zoom, bei dem alle Genauigkeitskreise ins Bild passen."""
    for zoom in range(13, 0, -1):
        boxes = []
        for point in points:
            x, y = _world(point["lat"], point["lon"], zoom)
            r = _radius_px(point, zoom)
            boxes.append((x - r, y - r, x + r, y + r))
        left, top = min(b[0] for b in boxes), min(b[1] for b in boxes)
        right, bottom = max(b[2] for b in boxes), max(b[3] for b in boxes)
        if right - left <= width - 2 * margin and bottom - top <= height - 2 * margin:
            return zoom, (left + right) / 2, (top + bottom) / 2
    x, y = _world(points[0]["lat"], points[0]["lon"], 1)
    return 1, x, y


def _tile(client, zoom, x, y):
    key = f"osm-tile:{zoom}:{x}:{y}"
    if (cached := cache.get(key)) is not None:
        return cached
    response = client.get(TILE_URL.format(z=zoom, x=x, y=y))
    response.raise_for_status()
    cache.set(key, response.content, TILE_CACHE_SECONDS)
    return response.content


def static_map(points, width=900, height=440, tiles=True):
    """PNG mit OSM-Hintergrund, Genauigkeitskreisen und nummerierten Punkten; None, wenn Kacheln fehlen.
    Mit tiles=False (Nur lokal) ohne Netzwerkzugriff auf neutralem Hintergrund."""
    from PIL import Image, ImageDraw, ImageFont

    if not points:
        return None
    zoom, cx, cy = _fit(points, width, height)
    left, top = cx - width / 2, cy - height / 2
    image = Image.new("RGBA", (width, height), "#e8e8e8")
    count = 2 ** zoom
    try:
        with httpx.Client(timeout=10, headers={"User-Agent": USER_AGENT}) as client:
            for ty in range(int(top // 256), int((top + height) // 256) + 1) if tiles else ():
                if not 0 <= ty < count:
                    continue
                for tx in range(int(left // 256), int((left + width) // 256) + 1):
                    tile = Image.open(io.BytesIO(_tile(client, zoom, tx % count, ty))).convert("RGBA")
                    image.paste(tile, (round(tx * 256 - left), round(ty * 256 - top)))
    except Exception:
        log.warning("OSM-Kacheln für das PDF nicht verfügbar", exc_info=True)
        return None

    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 13)
        small = ImageFont.truetype("DejaVuSans.ttf", 11)
    except OSError:
        font = small = ImageFont.load_default()
    for point in points:
        x, y = _world(point["lat"], point["lon"], zoom)
        x, y, r = x - left, y - top, _radius_px(point, zoom)
        rgb = tuple(int(point["farbe"][i:i + 2], 16) for i in (1, 3, 5))
        draw.ellipse((x - r, y - r, x + r, y + r), fill=(*rgb, 40), outline=(*rgb, 220), width=2)
    for point in points:
        x, y = _world(point["lat"], point["lon"], zoom)
        x, y = x - left, y - top
        draw.ellipse((x - 10, y - 10, x + 10, y + 10), fill=point["farbe"], outline="white", width=2)
        draw.text((x, y), str(point["nr"]), fill="white", font=font, anchor="mm")
    label = ATTRIBUTION if tiles else "Nur lokal: ohne Kartenhintergrund / local only: no basemap"
    text_box = draw.textbbox((0, 0), label, font=small)
    w, h = text_box[2] - text_box[0], text_box[3] - text_box[1]
    draw.rectangle((width - w - 10, height - h - 8, width, height), fill=(255, 255, 255, 200))
    draw.text((width - w - 5, height - h - 6), label, fill="#333", font=small)
    out = io.BytesIO()
    Image.alpha_composite(image, overlay).convert("RGB").save(out, "PNG", optimize=True)
    return out.getvalue()
