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
