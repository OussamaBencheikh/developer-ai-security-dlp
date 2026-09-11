CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE CHECK (char_length(email) <= 320),
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  email_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'security_admin', 'member', 'viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  critical_action TEXT NOT NULL DEFAULT 'block',
  high_action TEXT NOT NULL DEFAULT 'warn',
  medium_action TEXT NOT NULL DEFAULT 'warn',
  low_action TEXT NOT NULL DEFAULT 'allow',
  info_action TEXT NOT NULL DEFAULT 'allow',
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  secret_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  action TEXT NOT NULL CHECK (action IN ('allowed', 'warned', 'blocked', 'redacted')),
  service TEXT NOT NULL,
  extension_version TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX security_events_org_time_idx ON security_events (organization_id, occurred_at DESC);
CREATE INDEX organization_members_user_idx ON organization_members (user_id);
CREATE INDEX sessions_expiry_idx ON sessions (expires_at);

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY security_events_tenant_isolation ON security_events
  USING (organization_id::text = current_setting('app.organization_id', true));
CREATE POLICY policies_tenant_isolation ON policies
  USING (organization_id::text = current_setting('app.organization_id', true));

CREATE TABLE devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  device_identifier TEXT NOT NULL,
  extension_version TEXT NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  protection_status TEXT NOT NULL DEFAULT 'active',
  UNIQUE (organization_id, device_identifier)
);

CREATE TABLE plans (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  monthly_price_cents INTEGER NOT NULL CHECK (monthly_price_cents >= 0),
  entitlements JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL REFERENCES plans(id),
  provider TEXT NOT NULL DEFAULT 'none',
  provider_customer_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  current_period_end TIMESTAMPTZ
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE feature_flags (
  key TEXT PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT false,
  rollout_percent INTEGER NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100)
);

INSERT INTO plans (id, display_name, monthly_price_cents, entitlements) VALUES
  ('FREE', 'Free', 0, '["local_protection"]'),
  ('PRO', 'Pro', 0, '["local_protection", "advanced_rules"]'),
  ('TEAM', 'Team', 0, '["local_protection", "advanced_rules", "team_policies", "analytics"]'),
  ('ENTERPRISE', 'Enterprise', 0, '["local_protection", "advanced_rules", "team_policies", "analytics", "sso", "audit_export"]')
ON CONFLICT (id) DO NOTHING;
