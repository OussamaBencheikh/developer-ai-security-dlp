import type { Pool } from "pg";
import type { AuthUser, OrganizationRole } from "./auth.js";
import { can } from "./authorization.js";

export interface TeamMember {
  readonly userId: string;
  readonly email: string;
  readonly role: OrganizationRole;
}

export interface TeamService {
  list(organizationId: string): Promise<readonly TeamMember[]>;
  add(actor: AuthUser, email: string, role: OrganizationRole): Promise<TeamMember>;
  remove(actor: AuthUser, userId: string): Promise<void>;
}

const roles = new Set<OrganizationRole>(["owner", "admin", "security_admin", "member", "viewer"]);

export class InMemoryTeamService implements TeamService {
  private readonly members = new Map<string, TeamMember[]>();

  ensureOwner(user: AuthUser): void {
    const members = this.members.get(user.organizationId) ?? [];
    if (!members.some((member) => member.userId === user.id)) members.push({ userId: user.id, email: user.email, role: "owner" });
    this.members.set(user.organizationId, members);
  }

  async list(organizationId: string): Promise<readonly TeamMember[]> {
    return this.members.get(organizationId) ?? [];
  }

  async add(actor: AuthUser, email: string, role: OrganizationRole): Promise<TeamMember> {
    if (!can(actor.role, "team:manage") || !roles.has(role) || role === "owner") throw new Error("forbidden");
    const members = this.members.get(actor.organizationId) ?? [];
    const member: TeamMember = { userId: `pending_${members.length + 1}`, email: email.trim().toLowerCase(), role };
    if (!member.email.includes("@")) throw new Error("invalid_member");
    if (members.some((item) => item.email === member.email)) throw new Error("member_exists");
    members.push(member);
    this.members.set(actor.organizationId, members);
    return member;
  }

  async remove(actor: AuthUser, userId: string): Promise<void> {
    if (!can(actor.role, "team:manage")) throw new Error("forbidden");
    const members = this.members.get(actor.organizationId) ?? [];
    const target = members.find((member) => member.userId === userId);
    if (!target || target.role === "owner") throw new Error("not_found");
    this.members.set(actor.organizationId, members.filter((member) => member.userId !== userId));
  }
}

export class PostgresTeamService implements TeamService {
  constructor(private readonly pool: Pool) {}

  async list(organizationId: string): Promise<readonly TeamMember[]> {
    const result = await this.pool.query<TeamMember>(
      `SELECT u.id AS "userId", u.email, m.role FROM users u JOIN organization_members m ON m.user_id = u.id WHERE m.organization_id = $1 ORDER BY u.email`,
      [organizationId],
    );
    return result.rows;
  }

  async add(actor: AuthUser, email: string, role: OrganizationRole): Promise<TeamMember> {
    if (!can(actor.role, "team:manage") || !roles.has(role) || role === "owner") throw new Error("forbidden");
    const result = await this.pool.query<TeamMember>(
      `INSERT INTO organization_members (organization_id, user_id, role)
       SELECT $1, u.id, $3 FROM users u WHERE u.email = $2
       ON CONFLICT (organization_id, user_id) DO NOTHING
       RETURNING user_id AS "userId", $2 AS email, role`,
      [actor.organizationId, email.trim().toLowerCase(), role],
    );
    const member = result.rows[0];
    if (!member) throw new Error("member_not_found_or_exists");
    return member;
  }

  async remove(actor: AuthUser, userId: string): Promise<void> {
    if (!can(actor.role, "team:manage")) throw new Error("forbidden");
    const result = await this.pool.query(`DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2 AND role <> 'owner'`, [actor.organizationId, userId]);
    if (result.rowCount !== 1) throw new Error("not_found");
  }
}
