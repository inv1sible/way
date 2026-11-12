// Standortkarte: Leaflet mit OSM-Kacheln. Das Live-Update ersetzt den Abschnitt per innerHTML,
// deshalb wird jede neue Karte über einen MutationObserver initialisiert.
(() => {
  const init = (el) => {
    if (el.dataset.ready || typeof L === "undefined") return;
    el.dataset.ready = "1";
    const points = JSON.parse(el.dataset.points || "[]");
    const map = L.map(el, { scrollWheelZoom: false });
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    }).addTo(map);
    const bounds = L.latLngBounds([]);
    points.forEach((p) => {
      const circle = L.circle([p.lat, p.lon], {
        radius: p.genauigkeit_km * 1000, color: p.farbe, weight: 2, fillOpacity: 0.12,
      }).addTo(map);
      bounds.extend(circle.getBounds());
      L.marker([p.lat, p.lon], {
        icon: L.divIcon({ className: "", html: `<span class="geo-nr" style="background:${p.farbe}">${p.nr}</span>`, iconSize: [22, 22] }),
        title: p.quelle,
      }).addTo(map).bindPopup(document.createTextNode(`${p.nr}: ${p.quelle} – ${p.ort || ""} (± ${Math.round(p.genauigkeit_km)} km)`));
    });
    map.fitBounds(bounds, { padding: [20, 20] });
  };
  const scan = () => document.querySelectorAll(".geo-map").forEach(init);
  document.addEventListener("DOMContentLoaded", () => {
    scan();
    const live = document.getElementById("l-geo");
    if (live) new MutationObserver(scan).observe(live, { childList: true, subtree: true });
  });
})();
