import { describe, expect, it } from "vitest";
import { AuthStore } from "../src/auth.js";

describe("authentication store", () => {
  it("hashes passwords and issues expiring opaque sessions", () => {
    const store = new AuthStore();
    const user = store.register("Dev@Example.com", "a-strong-password");
    const login = store.login("dev@example.com", "a-strong-password");
    expect(user.email).toBe("dev@example.com");
    expect(login.sessionId).toHaveLength(43);
    expect(store.getUser(login.sessionId)).toMatchObject({ id: user.id, role: "owner" });
  });

  it("does not reveal whether an email exists through login errors", () => {
    const store = new AuthStore();
    store.register("dev@example.com", "a-strong-password");
    expect(() => store.login("dev@example.com", "wrong-password")).toThrow("invalid_credentials");
    expect(() => store.login("missing@example.com", "wrong-password")).toThrow("invalid_credentials");
  });
});
