chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  if (!message || typeof message !== "object" || !("type" in message)) return false;
  if (message.type === "security_event") {
    // Only metadata is eligible for future API delivery. Prompt content never crosses this boundary.
    sendResponse({ accepted: true });
  }
  return true;
});
