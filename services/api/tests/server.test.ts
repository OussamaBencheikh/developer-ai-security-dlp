import { describe, expect, it, afterEach } from "vitest";
import { createApiServer } from "../src/server.js";
import type { AddressInfo } from "node:net";

const servers: ReturnType<typeof createApiServer>[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function request(server: ReturnType<typeof createApiServer>, body?: unknown): Promise<Response> {
  if (!(server.address() as AddressInfo)?.port) await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  return fetch(`http://127.0.0.1:${port}/v1/security-events`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function authRequest(server: ReturnType<typeof createApiServer>, path: string, method: "GET" | "POST", body?: unknown, cookie?: string): Promise<Response> {
  if (!(server.address() as AddressInfo)?.port) await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
}

describe("metadata-only API", () => {
  it("accepts valid metadata and rejects secret-bearing fields", async () => {
    const server = createApiServer({ maxRequestsPerMinute: 10 });
    servers.push(server);
    const valid = await request(server, { eventType: "secret_detected", secretType: "github_token", severity: "critical", action: "redacted", service: "chatgpt", extensionVersion: "0.1.0" });
    const invalid = await request(server, { eventType: "secret_detected", token: "ghp_fake_value" });
    expect(valid.status).toBe(202);
    expect(invalid.status).toBe(400);
  });

  it("rate limits repeated requests", async () => {
    const server = createApiServer({ maxRequestsPerMinute: 1 });
    servers.push(server);
    const event = { eventType: "secret_detected", secretType: "github_token", severity: "high", action: "warned", service: "claude", extensionVersion: "0.1.0" };
    expect((await request(server, event)).status).toBe(202);
    const limited = await request(server, event);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBeTruthy();
  });

  it("registers, authenticates, reads, and logs out a session", async () => {
    const server = createApiServer({ maxRequestsPerMinute: 20 });
    servers.push(server);
    const register = await authRequest(server, "/v1/auth/register", "POST", { email: "dev@example.com", password: "a-strong-password" });
    const cookie = register.headers.get("set-cookie");
    expect(register.status).toBe(201);
    expect(cookie).toContain("HttpOnly");
    const me = await authRequest(server, "/v1/auth/me", "GET", undefined, cookie ?? undefined);
    expect(me.status).toBe(200);
    const logout = await authRequest(server, "/v1/auth/logout", "POST", undefined, cookie ?? undefined);
    expect(logout.status).toBe(204);
    expect((await authRequest(server, "/v1/auth/me", "GET", undefined, cookie ?? undefined)).status).toBe(401);
  });

  it("protects team and admin routes while exposing billing metadata", async () => {
    const server = createApiServer({ maxRequestsPerMinute: 30 });
    servers.push(server);
    const register = await authRequest(server, "/v1/auth/register", "POST", { email: "owner@example.com", password: "a-strong-password" });
    const cookie = register.headers.get("set-cookie") ?? undefined;
    expect((await authRequest(server, "/v1/team", "GET", undefined, cookie)).status).toBe(200);
    const add = await authRequest(server, "/v1/team/members", "POST", { email: "member@example.com", role: "member" }, cookie);
    expect(add.status).toBe(201);
    expect((await authRequest(server, "/v1/billing", "GET", undefined, cookie)).status).toBe(200);
    expect((await authRequest(server, "/v1/admin/health", "GET", undefined, cookie)).status).toBe(200);
    expect((await authRequest(server, "/v1/team", "GET")).status).toBe(401);
  });
});
