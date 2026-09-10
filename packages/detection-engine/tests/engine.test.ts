import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

describe("local detection engine", () => {
  it("detects developer secrets without returning their values", () => {
    const result = scan("const token = 'ghp_12345678901234567890';");
    expect(result.risk).toBe("critical");
    expect(result.detections[0]).toMatchObject({ category: "github_token", severity: "critical" });
    expect(JSON.stringify(result)).not.toContain("ghp_12345678901234567890");
  });

  it("ignores obvious placeholders", () => {
    expect(scan("OPENAI_API_KEY=YOUR_API_KEY").detections).toHaveLength(0);
  });

  it("detects private keys and database credentials", () => {
    const result = scan("postgres://app:strong-password@db.internal:5432/app\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----");
    expect(result.detections.map((item) => item.category)).toEqual(["database_url", "private_key"]);
  });
});
