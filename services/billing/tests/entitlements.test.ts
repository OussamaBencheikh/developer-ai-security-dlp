import { describe, expect, it } from "vitest";
import { featuresFor, hasFeature } from "../src/entitlements.js";

describe("billing entitlements", () => {
  it("keeps plan logic centralized", () => {
    expect(hasFeature("FREE", "local_protection")).toBe(true);
    expect(hasFeature("FREE", "analytics")).toBe(false);
    expect(hasFeature("TEAM", "team_policies")).toBe(true);
    expect(hasFeature("ENTERPRISE", "sso")).toBe(true);
    expect(featuresFor("PRO")).not.toContain("team_policies");
  });
});
