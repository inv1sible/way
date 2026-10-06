if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/service-worker", { scope: "/" }).catch(() => {});
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const field = document.querySelector(button.dataset.copy);
  navigator.clipboard.writeText(field.value).then(
    () => { button.textContent = "Kopiert"; },
    () => { field.select(); }
  );
});

// Datumsfeld "Stand": deutsche Hinweise statt der Meldung des Browsers (die sein Datumsformat und seine
// Sprache zeigt, z. B. "Value must be 10/05/2026 or earlier").
document.addEventListener("invalid", (event) => {
  const field = event.target;
  if (field.name !== "asof") return;
  const today = new Date(field.max).toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });
  field.setCustomValidity(
    field.validity.rangeOverflow ? `Der Stand kann nicht in der Zukunft liegen: bitte ${today} oder früher wählen.`
      : field.validity.rangeUnderflow ? "Der Stand liegt zu weit zurück: frühestens 01.01.2000."
      : "Bitte ein vollständiges Datum wählen (Tag, Monat, Jahr) oder das Feld leeren."
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
  button.textContent = ok ? "Kopiert ✓" : "Kopieren nicht möglich";
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
      const title = item.querySelector("summary").textContent.replace(/\s+Fehler\s*$/, "").trim();
      const raw = item.querySelector(".raw");
      return `### ${title}\n${raw ? raw.textContent.trim() : ""}`;
    });
    flash(all, await copyText(parts.join("\n\n")));
  }
});
