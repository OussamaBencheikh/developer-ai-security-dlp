# Extension

The extension uses Manifest V3, a module service worker, a content script, `chrome.storage`, and minimal permissions for ChatGPT, Claude, and Gemini.

The content script observes targeted text inputs and performs local scans. It never sends prompt text to the API. Current interception is a conservative foundation and uses a confirmation dialog; service-specific adapters and accessible in-page warning UI are required before production release.
