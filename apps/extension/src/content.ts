import { scan } from "@dlp/detection-engine";
import { redact } from "@dlp/redaction-engine";

const protectedHosts = new Set(["chatgpt.com", "claude.ai", "gemini.google.com"]);
const selectors = ["textarea", "[contenteditable='true']"];

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
  document.addEventListener("submit", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const input = target.querySelector<HTMLTextAreaElement>("textarea");
    if (!input) return;
    const result = scan(input.value);
    if (result.detections.length === 0) return;
    event.preventDefault();
    const shouldRedact = window.confirm(`${result.detections.length} security risks detected. OK to redact and send, Cancel to stop.`);
    if (shouldRedact) {
      setText(input, redact(input.value, result.detections));
      target.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    }
  }, true);
}

install();
