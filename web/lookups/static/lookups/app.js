if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/service-worker", { scope: "/" }).catch(() => {});
}

const ENGLISH = document.documentElement.lang.toLowerCase().startsWith("en");
const word = (german, english) => ENGLISH ? english : german;

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const field = document.querySelector(button.dataset.copy);
  navigator.clipboard.writeText(field.value).then(
    () => { button.textContent = word("Kopiert", "Copied"); },
    () => { field.select(); }
  );
});

// Datumsfeld "Stand": deutsche Hinweise statt der Meldung des Browsers (die sein Datumsformat und seine
// Sprache zeigt, z. B. "Value must be 10/05/2026 or earlier").
document.addEventListener("invalid", (event) => {
  const field = event.target;
  if (field.name !== "asof") return;
  const today = new Date(field.max).toLocaleDateString(ENGLISH ? "en-GB" : "de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });
  field.setCustomValidity(
    field.validity.rangeOverflow ? word(`Der Stand kann nicht in der Zukunft liegen: bitte ${today} oder früher wählen.`, `The reference date cannot be in the future: choose ${today} or earlier.`)
      : field.validity.rangeUnderflow ? word("Der Stand liegt zu weit zurück: frühestens 01.01.2000.", "The reference date is too far in the past: earliest 2000-01-01.")
      : word("Bitte ein vollständiges Datum wählen (Tag, Monat, Jahr) oder das Feld leeren.", "Enter a complete date or clear the field.")
  );
}, true);
document.addEventListener("input", (event) => {
  if (event.target.name === "asof") event.target.setCustomValidity("");
});

// Rohdaten in die Zwischenablage: je Quelle und alle zusammen. Arbeitet auf dem Seiteninhalt, daher auch
// mit Quellen, die erst während der Recherche nachgeladen wurden.
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    const area = document.createElement("textarea");  // Rückfall, z. B. ohne HTTPS
    area.value = text;
    area.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { /* bleibt false */ }
    area.remove();
    return ok;
  }
}

function flash(button, ok) {
  button.dataset.label = button.dataset.label || button.textContent;
  button.textContent = ok ? word("Kopiert ✓", "Copied ✓") : word("Kopieren nicht möglich", "Copy failed");
  clearTimeout(button.flashTimer);
  button.flashTimer = setTimeout(() => { button.textContent = button.dataset.label; }, 1600);
}

document.addEventListener("click", async (event) => {
  const single = event.target.closest("[data-copy-source]");
  if (single) {
    const raw = single.closest("details").querySelector(".raw");
    flash(single, await copyText(raw ? raw.textContent.trim() : ""));
    return;
  }
  const all = event.target.closest("[data-copy-all]");
  if (all) {
    const parts = [...document.querySelectorAll("#l-sources .src")].map((item) => {
      const title = item.querySelector("summary").textContent.replace(/\s+(Fehler|Error)\s*$/, "").trim();
      const raw = item.querySelector(".raw");
      return `### ${title}\n${raw ? raw.textContent.trim() : ""}`;
    });
    flash(all, await copyText(parts.join("\n\n")));
  }
});

// Verlauf: Analysen zum Löschen auswählen. Langer Druck auf eine Analyse (oder "Auswählen") startet die
// Auswahl, danach schaltet ein Tippen die Analyse um, statt sie zu öffnen.
(() => {
  const form = document.getElementById("history");
  if (!form || !form.querySelector("[data-pick-row]")) return;
  const boxes = () => [...form.querySelectorAll('input[name="ids"]')];
  const picking = () => form.classList.contains("picking");

  function refresh() {
    const count = boxes().filter((box) => box.checked).length;
    form.querySelector("[data-pick-count]").textContent = ENGLISH ? `${count} selected` : `${count} ausgewählt`;
    form.querySelector("[data-pick-delete]").disabled = count === 0;
    boxes().forEach((box) => box.closest("tr").classList.toggle("picked", box.checked));
  }
  function start(row) {
    form.classList.add("picking");
    const box = row && row.querySelector('input[name="ids"]');
    if (box && !box.disabled) box.checked = true;
    refresh();
  }
  function stop() {
    form.classList.remove("picking");
    boxes().forEach((box) => { box.checked = false; });
    refresh();
  }

  let timer = null, origin = null, longPressed = false;
  form.addEventListener("pointerdown", (event) => {
    const row = event.target.closest("[data-pick-row]");
    if (!row || picking() || event.button !== 0) return;
    origin = [event.clientX, event.clientY];
    longPressed = false;
    timer = setTimeout(() => {
      longPressed = true;
      start(row);
      if (navigator.vibrate) navigator.vibrate(20);
    }, 500);
  });
  const cancel = () => { clearTimeout(timer); timer = null; };
  form.addEventListener("pointerup", cancel);
  form.addEventListener("pointercancel", cancel);
  form.addEventListener("pointermove", (event) => {
    if (timer && Math.hypot(event.clientX - origin[0], event.clientY - origin[1]) > 10) cancel();
  });
  // Kein Kontextmenü des Browsers für den Link, solange der lange Druck die Auswahl startet
  form.addEventListener("contextmenu", (event) => {
    if (event.target.closest("[data-pick-row]")) event.preventDefault();
  });

  form.addEventListener("click", (event) => {
    if (event.target.closest("[data-pick-start]")) { start(null); return; }
    if (event.target.closest("[data-pick-cancel]")) { stop(); return; }
    const row = event.target.closest("[data-pick-row]");
    if (!row) return;
    if (longPressed) { event.preventDefault(); longPressed = false; return; }  // Loslassen nach langem Druck
    if (!picking()) return;
    const box = row.querySelector('input[name="ids"]');
    if (event.target !== box) {
      event.preventDefault();
      if (!box.disabled) box.checked = !box.checked;
    }
    refresh();
  });

  form.addEventListener("submit", (event) => {
    const chosen = boxes().filter((box) => box.checked);
    // Ein Eintrag kann mehrere Läufe derselben Abfrage umfassen (value "36,31,30")
    const runs = chosen.reduce((sum, box) => sum + box.value.split(",").length, 0);
    const question = runs === 1 ? word("Diese Analyse löschen?", "Delete this analysis?")
      : chosen.length === runs ? word(`${runs} Analysen löschen?`, `Delete ${runs} analyses?`)
      : word(`${chosen.length} Einträge mit zusammen ${runs} Analysen (alle Läufe) löschen?`,
        `Delete ${chosen.length} entries containing ${runs} analyses in total (all runs)?`);
    if (!chosen.length || !confirm(question)) event.preventDefault();
  });
})();

// Suchformular: Optionen sind nur für Netz-Ziele sinnvoll. Sie erscheinen ausschließlich, sobald die
// Eingabe wie ein Hostname/eine IP aussieht (Punkt bzw. Doppelpunkt für IPv6). Der Fokus allein ändert
// nichts. Für Rufnummern werden die ausgeblendeten Felder zusätzlich deaktiviert.
(() => {
  const form = document.getElementById("analyze");
  if (!form) return;
  const query = form.querySelector('input[name="q"]');
  const inputs = [...form.querySelectorAll(".opts input")];
  const isNetworkTarget = () => /[.:]/.test(query.value.trim());
  const sync = () => {
    const networkTarget = isNetworkTarget();
    inputs.forEach((input) => { input.disabled = !networkTarget; });
    form.classList.toggle("open", networkTarget);
  };
  form.classList.add("collapsible");
  sync();
  query.addEventListener("input", () => sync());
})();
