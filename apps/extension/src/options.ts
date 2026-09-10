import { defaultPolicy, type Policy, type PolicyAction } from "@dlp/detection-engine";

const form = document.querySelector<HTMLFormElement>("#policy-form");
const saved = document.querySelector<HTMLElement>("#saved");
const fields = ["critical", "high", "medium", "low"] as const;

void chrome.storage.local.get(["policy"]).then((settings) => {
  const policy = { ...defaultPolicy, ...(settings.policy as Partial<Policy> | undefined) };
  for (const field of fields) {
    const select = form?.elements.namedItem(field);
    if (select instanceof HTMLSelectElement) select.value = policy[field];
  }
});

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  const draft: Record<typeof fields[number], PolicyAction> = { ...defaultPolicy };
  for (const field of fields) {
    const select = form.elements.namedItem(field);
    if (select instanceof HTMLSelectElement) draft[field] = select.value as PolicyAction;
  }
  const policy: Policy = { ...defaultPolicy, ...draft };
  void chrome.storage.local.set({ policy }).then(() => {
    if (saved) saved.textContent = "Policy saved locally.";
  });
});