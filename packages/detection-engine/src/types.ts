export type SecretCategory =
  | "aws_access_key"
  | "aws_secret_key"
  | "github_token"
  | "gitlab_token"
  | "openai_key"
  | "anthropic_key"
  | "slack_token"
  | "private_key"
  | "jwt"
  | "database_url"
  | "stripe_key"
  | "sendgrid_key"
  | "azure_connection_string"
  | "internal_url"
  | "private_ip"
  | "generic_secret";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high" | "critical";
export type Sensitivity = "balanced" | "strict" | "permissive";
export type PolicyAction = "allow" | "warn" | "block";

export interface Policy {
  readonly critical: PolicyAction;
  readonly high: PolicyAction;
  readonly medium: PolicyAction;
  readonly low: PolicyAction;
  readonly info: PolicyAction;
}

export interface Detection {
  readonly category: SecretCategory;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly start: number;
  readonly end: number;
  readonly replacement: string;
  readonly detectorId: string;
}

export interface ScanResult {
  readonly detections: readonly Detection[];
  readonly risk: Severity;
  readonly scannedLength: number;
}

export interface PolicyDecision {
  readonly action: PolicyAction;
  readonly reason: Severity | "none";
}

export interface DetectorContext {
  readonly input: string;
  readonly start: number;
  readonly end: number;
  readonly candidate: string;
}

export interface Detector {
  readonly id: string;
  readonly category: SecretCategory;
  readonly severity: Severity;
  readonly pattern: RegExp;
  detect(context: DetectorContext): boolean;
}
