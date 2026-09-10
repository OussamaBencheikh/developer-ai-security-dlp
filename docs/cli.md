# CLI

The local CLI reuses the same detection engine as the browser extension and never sends scanned content to the API.

```sh
npm run build -w @dlp/cli
node apps/cli/dist/index.js scan README.md
printf 'password=Correct-Horse-Battery-123' | node apps/cli/dist/index.js scan
node apps/cli/dist/index.js scan . --strict
```

Exit codes:

- `0`: no detection.
- `1`: sensitive content detected.
- `2`: invalid usage or unreadable input.

Output contains only file names, categories, severity, and counts. It does not print secret values or full source content.

## Pre-commit

After `npm install`, the repository configures `.githooks/pre-commit`. It scans staged supported files and blocks a commit when a likely secret is detected. The hook can be disabled for a local checkout with `git config --unset-all core.hooksPath`.
