// Aktualisiert die Analyse-Seite während der Recherche, ohne sie neu zu laden: Vorhandene
// Elemente bleiben unangetastet, solange sich ihr Inhalt nicht ändert; aufgeklappte Rohdaten,
// markierter Text und die Scrollposition bleiben erhalten.
(() => {
  const root = document.getElementById("live");
  if (!root || !root.dataset.running) return;

  const sources = document.getElementById("l-sources");
  const sourcesHeading = document.getElementById("l-sources-h");
  const conn = document.getElementById("l-conn");
  let rev = root.dataset.rev;
  let failures = 0;

  const setFragment = (name, fragment) => {
    const el = document.getElementById("l-" + name);
    if (!el || el.dataset.h === fragment.h) return;
    el.innerHTML = fragment.html;
    el.dataset.h = fragment.h;
  };

  const setSource = (source) => {
    let el = [...sources.children].find((child) => child.dataset.key === source.key);
    if (!el) {
      el = document.createElement("div");
      el.className = "src";
      el.dataset.key = source.key;
      sources.appendChild(el);
    } else if (el.dataset.h === source.h) {
      return;
    }
    const wasOpen = el.querySelector("details")?.open;
    el.innerHTML = source.html;
    el.dataset.h = source.h;
    if (wasOpen) el.querySelector("details").open = true;
  };

  const apply = (data) => {
    rev = data.rev;
    if (data.unchanged) return;
    for (const [name, fragment] of Object.entries(data.fragments)) setFragment(name, fragment);
    data.sources.forEach(setSource);
    [...sources.children]
      .sort((left, right) => left.dataset.key.localeCompare(right.dataset.key, undefined, { sensitivity: "base" }))
      .forEach((source) => sources.appendChild(source));
    sourcesHeading.hidden = data.sources.length === 0;
  };

  const poll = async () => {
    try {
      const response = await fetch(`${root.dataset.url}?rev=${encodeURIComponent(rev)}`, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.headers.get("Content-Type")?.includes("json")) {
        // Sitzung abgelaufen: die Anmeldeseite kam statt JSON
        window.location.reload();
        return;
      }
      const data = await response.json();
      failures = 0;
      conn.hidden = true;
      apply(data);
      if (!data.running) return;
    } catch (error) {
      failures += 1;
      if (failures >= 3) conn.hidden = false;
    }
    setTimeout(poll, Math.min(2000 * (1 + failures), 10000) * (document.hidden ? 3 : 1));
  };

  setTimeout(poll, 1500);
})();
