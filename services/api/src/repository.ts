import type { Pool, PoolClient } from "pg";
import type { OrganizationRole } from "./auth.js";

export interface OrganizationSummary {
  readonly id: string;
  readonly name: string;
  readonly role: OrganizationRole;
  readonly memberCount: number;
}

export interface DashboardSummary {
  readonly protectedDevices: number;
  readonly detections: number;
  readonly blockedEvents: number;
  readonly redactions: number;
  readonly recentEvents: readonly {
    readonly occurredAt: string;
    readonly service: string;
    readonly secretType: string;
    readonly severity: string;
    readonly action: string;
  }[];
}

export class OrganizationRepository {
  constructor(private readonly pool: Pool) {}

  async withTenant<T>(organizationId: string, callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.organization_id', $1, true)", [organizationId]);
      const result = await callback(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getOrganizationForUser(userId: string, organizationId: string): Promise<OrganizationSummary | null> {
    return this.withTenant(organizationId, async (client) => {
      const result = await client.query<{ id: string; name: string; role: OrganizationRole; member_count: string }>(
        `SELECT o.id, o.name, m.role, COUNT(all_members.user_id)::text AS member_count
         FROM organizations o
         JOIN organization_members m ON m.organization_id = o.id AND m.user_id = $1
         JOIN organization_members all_members ON all_members.organization_id = o.id
         WHERE o.id = $2
         GROUP BY o.id, o.name, m.role`,
        [userId, organizationId],
      );
      const row = result.rows[0];
      return row ? { id: row.id, name: row.name, role: row.role, memberCount: Number(row.member_count) } : null;
    });
  }

  async getDashboardSummary(organizationId: string): Promise<DashboardSummary> {
    return this.withTenant(organizationId, async (client) => {
      const [counts, recent] = await Promise.all([
        client.query<{ detections: string; blocked: string; redactions: string }>(
          `SELECT COUNT(*)::text AS detections,
             COUNT(*) FILTER (WHERE action = 'blocked')::text AS blocked,
             COUNT(*) FILTER (WHERE action = 'redacted')::text AS redactions
           FROM security_events WHERE organization_id = current_setting('app.organization_id')::uuid`,
        ),
        client.query<{ occurred_at: string; service: string; secret_type: string; severity: string; action: string }>(
          `SELECT occurred_at, service, secret_type, severity, action
           FROM security_events WHERE organization_id = current_setting('app.organization_id')::uuid
           ORDER BY occurred_at DESC LIMIT 10`,
        ),
      ]);
      const row = counts.rows[0];
      return {
        protectedDevices: 0,
        detections: Number(row?.detections ?? 0),
        blockedEvents: Number(row?.blocked ?? 0),
        redactions: Number(row?.redactions ?? 0),
        recentEvents: recent.rows.map((event) => ({ occurredAt: event.occurred_at, service: event.service, secretType: event.secret_type, severity: event.severity, action: event.action })),
      };
    });
  }
}
