import { describe, expect, it } from "vitest";
import { scan } from "../../detection-engine/src/index.js";
import { redact } from "../src/index.js";

describe("redaction engine", () => {
  it("preserves surrounding code while replacing detected spans", () => {
    const source = "const key = 'ghp_12345678901234567890';";
    const result = redact(source, scan(source).detections);
    expect(result).toBe("const key = '[REDACTED_GITHUB_TOKEN]';");
    expect(result).not.toContain("ghp_");
  });
});
