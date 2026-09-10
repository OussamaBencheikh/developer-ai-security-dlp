import { describe, expect, it } from "vitest";
import { decide, defaultPolicy, scan } from "../src/index.js";

describe("security policy", () => {
  it("blocks critical findings by default", () => {
    expect(decide(scan("const key = 'ghp_12345678901234567890';"))).toEqual({ action: "block", reason: "critical" });
  });

  it("allows a configured medium finding", () => {
    const result = scan("DATABASE_URL=postgres://app:password@db.internal/app");
    expect(decide(result, { ...defaultPolicy, high: "allow" })).toEqual({ action: "allow", reason: "high" });
  });

  it("keeps the strongest action across different findings", () => {
    const result = scan("const token = 'ghp_12345678901234567890';\nDATABASE_URL=postgres://app:password@db.internal/app");
    expect(decide(result, { ...defaultPolicy, critical: "allow" })).toEqual({ action: "warn", reason: "high" });
  });
});