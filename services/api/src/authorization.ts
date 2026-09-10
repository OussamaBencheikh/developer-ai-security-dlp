import type { OrganizationRole } from "./auth.js";

export type Permission = "organization:read" | "team:manage" | "policy:manage" | "events:read" | "billing:manage" | "admin:access";

const rolePermissions: Record<OrganizationRole, readonly Permission[]> = {
  owner: ["organization:read", "team:manage", "policy:manage", "events:read", "billing:manage"],
  admin: ["organization:read", "team:manage", "policy:manage", "events:read", "billing:manage"],
  security_admin: ["organization:read", "policy:manage", "events:read"],
  member: ["organization:read", "events:read"],
  viewer: ["organization:read", "events:read"],
};

export function can(role: OrganizationRole, permission: Permission): boolean {
  return rolePermissions[role].includes(permission);
}

export function assertPermission(role: OrganizationRole, permission: Permission): void {
  if (!can(role, permission)) throw new Error("forbidden");
}
