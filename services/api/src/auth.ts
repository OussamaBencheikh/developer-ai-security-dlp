import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export type OrganizationRole = "owner" | "admin" | "security_admin" | "member" | "viewer";

export interface AuthUser {
  readonly id: string;
  readonly email: string;
  readonly organizationId: string;
  readonly role: OrganizationRole;
}

interface StoredUser extends AuthUser {
  readonly passwordHash: Buffer;
  readonly salt: Buffer;
}

interface Session {
  readonly userId: string;
  readonly expiresAt: number;
}

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const minimumPasswordLength = 12;

export class AuthStore {
  private readonly usersByEmail = new Map<string, StoredUser>();
  private readonly usersById = new Map<string, StoredUser>();
  private readonly sessions = new Map<string, Session>();

  register(email: string, password: string): AuthUser {
    const normalizedEmail = email.trim().toLowerCase();
    if (!emailPattern.test(normalizedEmail) || password.length < minimumPasswordLength) throw new Error("invalid_credentials");
    if (this.usersByEmail.has(normalizedEmail)) throw new Error("account_exists");
    const salt = randomBytes(16);
    const user: StoredUser = {
      id: `usr_${randomBytes(12).toString("hex")}`,
      email: normalizedEmail,
      organizationId: `org_${randomBytes(12).toString("hex")}`,
      role: "owner",
      salt,
      passwordHash: scryptSync(password, salt, 64),
    };
    this.usersByEmail.set(user.email, user);
    this.usersById.set(user.id, user);
    return this.publicUser(user);
  }

  login(email: string, password: string): { user: AuthUser; sessionId: string } {
    const user = this.usersByEmail.get(email.trim().toLowerCase());
    if (!user) throw new Error("invalid_credentials");
    const candidate = scryptSync(password, user.salt, 64);
    if (!timingSafeEqual(candidate, user.passwordHash)) throw new Error("invalid_credentials");
    const sessionId = randomBytes(32).toString("base64url");
    this.sessions.set(sessionId, { userId: user.id, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
    return { user: this.publicUser(user), sessionId };
  }

  getUser(sessionId: string | undefined): AuthUser | null {
    if (!sessionId) return null;
    const session = this.sessions.get(sessionId);
    if (!session || session.expiresAt <= Date.now()) {
      this.sessions.delete(sessionId);
      return null;
    }
    const user = this.usersById.get(session.userId);
    return user ? this.publicUser(user) : null;
  }

  logout(sessionId: string | undefined): void {
    if (sessionId) this.sessions.delete(sessionId);
  }

  organizationFor(userId: string): { id: string; name: string; role: OrganizationRole; memberCount: number } | null {
    const user = this.usersById.get(userId);
    return user ? { id: user.organizationId, name: `${user.email}'s organization`, role: user.role, memberCount: 1 } : null;
  }

  private publicUser(user: StoredUser): AuthUser {
    return { id: user.id, email: user.email, organizationId: user.organizationId, role: user.role };
  }
}
