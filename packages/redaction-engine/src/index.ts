import type { Detection } from "@dlp/detection-engine";

export function redact(input: string, detections: readonly Detection[]): string {
  return [...detections]
    .sort((a, b) => b.start - a.start)
    .reduce((result, detection) => result.slice(0, detection.start) + detection.replacement + result.slice(detection.end), input);
}
