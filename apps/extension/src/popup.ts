const status = document.querySelector<HTMLElement>("#status");
chrome.storage.local.get(["enabled"], (settings) => {
  const enabled = settings.enabled !== false;
  if (status) status.textContent = enabled ? "Protection is active" : "Protection is paused";
});
