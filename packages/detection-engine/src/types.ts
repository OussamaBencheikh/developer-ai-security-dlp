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
  | "generic_secret";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high" | "critical";
export type Sensitivity = "balanced" | "strict" | "permissive";

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
