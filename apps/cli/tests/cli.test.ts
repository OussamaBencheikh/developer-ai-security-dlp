import { describe, expect, it } from "vitest";
import { scan } from "../../../packages/detection-engine/src/index.js";

describe("CLI scan contract", () => {
  it("uses the shared local engine and returns metadata-only findings", () => {
    const result = scan("const token = 'ghp_12345678901234567890';");
    expect(result.detections[0]?.category).toBe("github_token");
    expect(JSON.stringify(result)).not.toContain("ghp_12345678901234567890");
  });
});
