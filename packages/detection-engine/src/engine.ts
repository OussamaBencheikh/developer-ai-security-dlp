import { detectors } from "./detectors.js";
import type { Confidence, Detection, ScanResult, Sensitivity, Severity } from "./types.js";

const severityRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function confidenceFor(detectorId: string, candidate: string): Confidence {
  if (["private-key", "aws-access-key", "openai-key", "anthropic-key"].includes(detectorId)) return "critical";
  if (candidate.length >= 32) return "high";
  return "medium";
}

function allowedBySensitivity(severity: Severity, sensitivity: Sensitivity): boolean {
  if (sensitivity === "strict") return true;
  if (sensitivity === "permissive") return severityRank[severity] >= severityRank.medium;
  return severityRank[severity] >= severityRank.low;
}

export function scan(input: string, sensitivity: Sensitivity = "balanced"): ScanResult {
  const detections: Detection[] = [];
  for (const detector of detectors) {
    detector.pattern.lastIndex = 0;
    for (const match of input.matchAll(detector.pattern)) {
      const candidate = match[0];
      const start = match.index ?? 0;
      const end = start + candidate.length;
      if (!detector.detect({ input, start, end, candidate }) || !allowedBySensitivity(detector.severity, sensitivity)) continue;
      detections.push({
        category: detector.category,
        severity: detector.severity,
        confidence: confidenceFor(detector.id, candidate),
        start,
        end,
        replacement: `[REDACTED_${detector.category.toUpperCase()}]`,
        detectorId: detector.id,
      });
    }
  }
  const unique = detections.filter((detection, index, all) => all.findIndex((item) => item.start === detection.start && item.end === detection.end) === index);
  const risk = unique.reduce<Severity>((current, detection) => severityRank[detection.severity] > severityRank[current] ? detection.severity : current, "info");
  return { detections: unique.sort((a, b) => a.start - b.start), risk, scannedLength: input.length };
}
