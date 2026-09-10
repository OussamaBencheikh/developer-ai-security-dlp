import type { Detector, DetectorContext } from "./types.js";

const placeholderPattern = /^(?:<[^>]+>|\[?redacted\]?|your[_ -]?(?:api[_ -]?)?key|replace[_ -]?me|example|changeme|dummy|test|secret)$/i;

function isHighEntropy(candidate: string): boolean {
  if (candidate.length < 16) return false;
  const counts = new Map<string, number>();
  for (const character of candidate) counts.set(character, (counts.get(character) ?? 0) + 1);
  const entropy = [...counts.values()].reduce((sum, count) => {
    const probability = count / candidate.length;
    return sum - probability * Math.log2(probability);
  }, 0);
  return entropy >= 3.2;
}

function hasSecretContext(context: DetectorContext): boolean {
  const nearby = context.input.slice(Math.max(0, context.start - 80), Math.min(context.input.length, context.end + 80));
  return /(?:secret|token|password|passwd|credential|api[_ -]?key|private[_ -]?key|authorization|bearer)/i.test(nearby);
}

function structuredCandidate(context: DetectorContext): boolean {
  return !placeholderPattern.test(context.candidate) && (isHighEntropy(context.candidate) || hasSecretContext(context));
}

export const detectors: readonly Detector[] = [
  {
    id: "aws-access-key",
    category: "aws_access_key",
    severity: "critical",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    detect: () => true,
  },
  {
    id: "aws-secret-key",
    category: "aws_secret_key",
    severity: "critical",
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,
    detect: (context) => structuredCandidate({ ...context, candidate: context.candidate.replace(/^.*?[=:]\s*["']?/, "").replace(/["']?\s*$/, "") }),
  },
  {
    id: "github-token",
    category: "github_token",
    severity: "critical",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    detect: (context) => context.candidate.length >= 20,
  },
  {
    id: "gitlab-token",
    category: "gitlab_token",
    severity: "high",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    detect: () => true,
  },
  {
    id: "openai-key",
    category: "openai_key",
    severity: "critical",
    pattern: /\bsk-[A-Za-z0-9]{20,}\b/g,
    detect: (context) => !placeholderPattern.test(context.candidate),
  },
  {
    id: "anthropic-key",
    category: "anthropic_key",
    severity: "critical",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    detect: () => true,
  },
  {
    id: "slack-token",
    category: "slack_token",
    severity: "high",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    detect: () => true,
  },
  {
    id: "private-key",
    category: "private_key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    detect: () => true,
  },
  {
    id: "jwt",
    category: "jwt",
    severity: "high",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    detect: (context) => context.candidate.split(".").length === 3,
  },
  {
    id: "database-url",
    category: "database_url",
    severity: "high",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"']+/gi,
    detect: (context) => /:\/\/[^:@/\s]+:[^@/\s]+@/i.test(context.candidate),
  },
  {
    id: "stripe-key",
    category: "stripe_key",
    severity: "critical",
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    detect: (context) => !/test[_ -]?(?:key|value)|example/i.test(context.input.slice(Math.max(0, context.start - 60), context.end + 60)),
  },
  {
    id: "sendgrid-key",
    category: "sendgrid_key",
    severity: "high",
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    detect: () => true,
  },
  {
    id: "azure-connection-string",
    category: "azure_connection_string",
    severity: "high",
    pattern: /\bDefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[^;\s]+[^\n]*/gi,
    detect: (context) => !placeholderPattern.test(context.candidate),
  },
  {
    id: "internal-url",
    category: "internal_url",
    severity: "medium",
    pattern: /\bhttps?:\/\/[a-z0-9.-]+\.(?:internal|local|corp|intranet)(?::\d+)?(?:\/[^\s]*)?/gi,
    detect: () => true,
  },
  {
    id: "private-ip",
    category: "private_ip",
    severity: "medium",
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    detect: () => true,
  },
  {
    id: "generic-assignment",
    category: "generic_secret",
    severity: "high",
    pattern: /\b(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|PASSWORD|CLIENT_SECRET)\s*[=:]\s*["']([^"'\s]{12,})["']/gi,
    detect: (context) => structuredCandidate({ ...context, candidate: context.candidate.replace(/^.*?[=:]\s*["']/, "").replace(/["']$/, "") }),
  },
];
