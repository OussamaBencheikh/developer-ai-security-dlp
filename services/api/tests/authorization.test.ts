import { describe, expect, it } from "vitest";
import { assertPermission, can } from "../src/authorization.js";

describe("organization authorization", () => {
  it("separates team, policy, billing, and viewer capabilities", () => {
    expect(can("owner", "billing:manage")).toBe(true);
    expect(can("security_admin", "policy:manage")).toBe(true);
    expect(can("security_admin", "billing:manage")).toBe(false);
    expect(can("viewer", "team:manage")).toBe(false);
  });

  it("rejects forbidden actions", () => {
    expect(() => assertPermission("member", "team:manage")).toThrow("forbidden");
  });
});
