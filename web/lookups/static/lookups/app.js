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
