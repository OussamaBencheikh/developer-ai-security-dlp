import { decide, defaultPolicy, scan, type Policy, type PolicyAction, type ScanResult } from "@dlp/detection-engine";
import { redact } from "@dlp/redaction-engine";

const protectedHosts = new Set(["chatgpt.com", "claude.ai", "gemini.google.com"]);
const selectors = ["textarea", "[contenteditable='true']"];
let policy: Policy = defaultPolicy;
let allowNextSubmit = false;

void chrome.storage.local.get(["policy"]).then((settings) => {
  if (settings.policy && typeof settings.policy === "object") policy = { ...defaultPolicy, ...settings.policy } as Policy;
});

function getText(element: Element): string {
  return element instanceof HTMLTextAreaElement ? element.value : element.textContent ?? "";
}

function setText(element: Element, value: string): void {
  if (element instanceof HTMLTextAreaElement) {
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    setter?.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
  } else {
    element.textContent = value;
    element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
  }
}

function inspect(element: Element): void {
  const source = getText(element);
  const result = scan(source);
  element.toggleAttribute("data-dlp-risk", result.detections.length > 0);
  element.setAttribute("aria-description", result.detections.length > 0 ? `${result.detections.length} security risks detected` : "");
}

function removeWarning(): void {
  document.querySelector("[data-dlp-warning]")?.remove();
}

function showWarning(result: ScanResult, action: PolicyAction, onRedact: () => void, onSendAnyway: () => void): void {
  removeWarning();
  const backdrop = document.createElement("div");
  backdrop.dataset.dlpWarning = "true";
  backdrop.setAttribute("role", "presentation");
  backdrop.innerHTML = `
    <div role="dialog" aria-modal="true" aria-labelledby="dlp-warning-title">
      <h2 id="dlp-warning-title">${result.detections.length} security risk${result.detections.length === 1 ? "" : "s"} detected</h2>
      <p>This message may contain sensitive developer information. Your content stays in this browser.</p>
      <p><strong>Policy:</strong> ${action === "block" ? "Sending is blocked until risks are removed." : "Review before sending."}</p>
      <div data-dlp-actions>
        <button type="button" data-dlp-redact>Redact &amp; Send</button>
        <button type="button" data-dlp-cancel>Cancel</button>
        ${action === "warn" ? '<button type="button" data-dlp-anyway>Send Anyway</button>' : ""}
      </div>
    </div>`;
  const style = document.createElement("style");
  style.textContent = `[data-dlp-warning]{position:fixed;inset:0;z-index:2147483647;background:rgba(15,23,42,.55);display:grid;place-items:center;font:14px system-ui,sans-serif}[data-dlp-warning]>div{max-width:440px;margin:16px;padding:24px;background:#fff;color:#111827;border:1px solid #f59e0b;border-radius:10px;box-shadow:0 16px 48px rgba(0,0,0,.25)}[data-dlp-warning] h2{margin:0 0 12px;font-size:20px}[data-dlp-warning] p{line-height:1.5}[data-dlp-actions]{display:flex;flex-wrap:wrap;gap:8px;margin-top:20px}[data-dlp-warning] button{border:0;border-radius:6px;padding:9px 12px;cursor:pointer;font-weight:600}[data-dlp-redact]{background:#b45309;color:#fff}[data-dlp-cancel]{background:#e5e7eb;color:#111827}[data-dlp-anyway]{background:transparent;color:#92400e}`;
  backdrop.prepend(style);
  backdrop.querySelector("[data-dlp-redact]")?.addEventListener("click", () => { removeWarning(); onRedact(); });
  backdrop.querySelector("[data-dlp-cancel]")?.addEventListener("click", removeWarning);
  backdrop.querySelector("[data-dlp-anyway]")?.addEventListener("click", () => { removeWarning(); onSendAnyway(); });
  document.documentElement.append(backdrop);
  backdrop.querySelector<HTMLButtonElement>("[data-dlp-redact]")?.focus();
}

function findInput(target: Element): Element | null {
  return target.matches(selectors.join(",")) ? target : target.querySelector(selectors.join(","));
}

function protectSubmit(event: Event): void {
  if (allowNextSubmit) {
    allowNextSubmit = false;
    return;
  }
  const target = event.target;
  if (!(target instanceof Element)) return;
  const input = findInput(target);
  if (!input) return;
  const source = getText(input);
  const result = scan(source);
  if (result.detections.length === 0) return;
  const decision = decide(result, policy);
  event.preventDefault();
  showWarning(result, decision.action, () => {
    setText(input, redact(source, result.detections));
    allowNextSubmit = true;
    target.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  }, () => {
    allowNextSubmit = true;
    target.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}

function install(): void {
  if (!protectedHosts.has(location.hostname)) return;
  const observer = new MutationObserver(() => {
    for (const selector of selectors) document.querySelectorAll(selector).forEach((element) => {
      if (element.getAttribute("data-dlp-bound") === "true") return;
      element.setAttribute("data-dlp-bound", "true");
      element.addEventListener("input", () => inspect(element), { passive: true });
      inspect(element);
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener("submit", protectSubmit, true);
}

install();
