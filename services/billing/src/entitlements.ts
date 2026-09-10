export type Plan = "FREE" | "PRO" | "TEAM" | "ENTERPRISE";
export type Feature = "local_protection" | "advanced_rules" | "team_policies" | "analytics" | "sso" | "audit_export";

const entitlements: Record<Plan, readonly Feature[]> = {
  FREE: ["local_protection"],
  PRO: ["local_protection", "advanced_rules"],
  TEAM: ["local_protection", "advanced_rules", "team_policies", "analytics"],
  ENTERPRISE: ["local_protection", "advanced_rules", "team_policies", "analytics", "sso", "audit_export"],
};

export function hasFeature(plan: Plan, feature: Feature): boolean {
  return entitlements[plan].includes(feature);
}

export function featuresFor(plan: Plan): readonly Feature[] {
  return entitlements[plan];
}
