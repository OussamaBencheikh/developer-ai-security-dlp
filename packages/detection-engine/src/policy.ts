import type { Policy, PolicyDecision, PolicyAction, ScanResult, Severity } from "./types.js";

export const defaultPolicy: Policy = {
  critical: "block",
  high: "warn",
  medium: "warn",
  low: "allow",
  info: "allow",
};

const rank: Record<PolicyAction, number> = { allow: 0, warn: 1, block: 2 };
const severities: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function decide(result: ScanResult, policy: Policy = defaultPolicy): PolicyDecision {
  let selected: PolicyDecision = { action: "allow", reason: "none" };
  for (const detection of result.detections) {
    const action = policy[detection.severity];
    if (rank[action] > rank[selected.action]) selected = { action, reason: detection.severity };
  }
  if (selected.reason !== "none") return selected;
  for (const severity of severities) {
    if (result.detections.some((detection) => detection.severity === severity)) {
      const action = policy[severity];
      return { action, reason: severity };
    }
  }
  return selected;
}

export function mergePolicy(base: Policy, override: Partial<Policy>): Policy {
  return { ...base, ...override };
}

export function strongerAction(left: PolicyAction, right: PolicyAction): PolicyAction {
  return rank[left] >= rank[right] ? left : right;
}