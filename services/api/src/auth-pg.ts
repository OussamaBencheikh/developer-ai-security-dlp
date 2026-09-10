import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { Pool } from "pg";
import type { AuthUser, OrganizationRole } from "./auth.js";

function hashSession(sessionId: string): string {
  return createHash("sha256").update(sessionId).digest("hex");
}

export class PostgresAuthStore {
  constructor(private readonly pool: Pool) {}

  async register(email: string, password: string): Promise<AuthUser> {
    const normalizedEmail = email.trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(normalizedEmail) || password.length < 12) throw new Error("invalid_credentials");
    const salt = randomBytes(16);
    const passwordHash = scryptSync(password, salt, 64).toString("base64");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const user = await client.query<{ id: string }>("INSERT INTO users (email, password_hash, password_salt) VALUES ($1, $2, $3) RETURNING id", [normalizedEmail, passwordHash, salt.toString("base64")]);
      const userId = user.rows[0]?.id;
      if (!userId) throw new Error("registration_failed");
      const organization = await client.query<{ id: string }>("INSERT INTO organizations (name) VALUES ($1) RETURNING id", [`${normalizedEmail}'s organization`]);
      const organizationId = organization.rows[0]?.id;
      if (!organizationId) throw new Error("registration_failed");
      await client.query("INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'owner')", [organizationId, userId]);
      await client.query("COMMIT");
      return { id: userId, email: normalizedEmail, organizationId, role: "owner" };
    } catch (error) {
      await client.query("ROLLBACK");
      if (error instanceof Error && "code" in error && error.code === "23505") throw new Error("account_exists");
      throw error;
    } finally {
      client.release();
    }
  }

  async login(email: string, password: string): Promise<{ user: AuthUser; sessionId: string }> {
    const result = await this.pool.query<{ id: string; email: string; password_hash: string; password_salt: string; organization_id: string; role: OrganizationRole }>(
      `SELECT u.id, u.email, u.password_hash, u.password_salt, m.organization_id, m.role
       FROM users u JOIN organization_members m ON m.user_id = u.id
       WHERE u.email = $1 LIMIT 1`, [email.trim().toLowerCase()],
    );
    const row = result.rows[0];
    if (!row) throw new Error("invalid_credentials");
    const candidate = scryptSync(password, Buffer.from(row.password_salt, "base64"), 64);
    if (!timingSafeEqual(candidate, Buffer.from(row.password_hash, "base64"))) throw new Error("invalid_credentials");
    const sessionId = randomBytes(32).toString("base64url");
    await this.pool.query("INSERT INTO sessions (id_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '8 hours')", [hashSession(sessionId), row.id]);
    return { user: { id: row.id, email: row.email, organizationId: row.organization_id, role: row.role }, sessionId };
  }

  async getUser(sessionId: string | undefined): Promise<AuthUser | null> {
    if (!sessionId) return null;
    const result = await this.pool.query<{ id: string; email: string; organization_id: string; role: OrganizationRole }>(
      `SELECT u.id, u.email, m.organization_id, m.role FROM sessions s JOIN users u ON u.id = s.user_id
       JOIN organization_members m ON m.user_id = u.id WHERE s.id_hash = $1 AND s.expires_at > now() LIMIT 1`, [hashSession(sessionId)],
    );
    const row = result.rows[0];
    return row ? { id: row.id, email: row.email, organizationId: row.organization_id, role: row.role } : null;
  }

  async logout(sessionId: string | undefined): Promise<void> {
    if (sessionId) await this.pool.query("DELETE FROM sessions WHERE id_hash = $1", [hashSession(sessionId)]);
  }

  async organizationFor(userId: string): Promise<{ id: string; name: string; role: OrganizationRole; memberCount: number } | null> {
    const result = await this.pool.query<{ id: string; name: string; role: OrganizationRole; member_count: string }>(
      `SELECT o.id, o.name, m.role, COUNT(all_members.user_id)::text AS member_count
       FROM organizations o JOIN organization_members m ON m.organization_id = o.id AND m.user_id = $1
       JOIN organization_members all_members ON all_members.organization_id = o.id
       GROUP BY o.id, o.name, m.role`, [userId],
    );
    const row = result.rows[0];
    return row ? { id: row.id, name: row.name, role: row.role, memberCount: Number(row.member_count) } : null;
  }
}
