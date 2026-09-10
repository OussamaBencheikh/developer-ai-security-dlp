#!/usr/bin/env node
import { readdir, readFile } from "node:fs/promises";
import { basename, extname, join, relative, resolve } from "node:path";
import { stdin } from "node:process";
import { scan, type Detection, type Sensitivity } from "@dlp/detection-engine";

const ignoredDirectories = new Set([".git", "node_modules", "dist", "coverage"]);
const supportedExtensions = new Set([".env", ".json", ".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".yaml", ".yml", ".sh", ".sql", ".txt", ".md"]);

interface Finding {
  readonly file: string;
  readonly categories: readonly string[];
  readonly severity: string;
  readonly count: number;
}

async function collectFiles(target: string): Promise<string[]> {
  const absolute = resolve(target);
  const entries = await readdir(absolute, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) files.push(...await collectFiles(join(absolute, entry.name)));
    } else if (supportedExtensions.has(extname(entry.name).toLowerCase()) || basename(entry.name).startsWith(".env")) {
      files.push(join(absolute, entry.name));
    }
  }
  return files;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function summarize(file: string, detections: readonly Detection[], root: string): Finding {
  return {
    file: relative(root, file) || "stdin",
    categories: [...new Set(detections.map((detection) => detection.category))],
    severity: detections.reduce((current, detection) => detection.severity === "critical" ? "critical" : current === "critical" ? current : detection.severity, "info"),
    count: detections.length,
  };
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const command = args[0];
  const sensitivity = args.includes("--strict") ? "strict" : args.includes("--permissive") ? "permissive" : "balanced";
  if (command !== "scan") {
    console.error("Usage: dlp scan [file-or-directory ...] [--strict|--permissive]");
    return 2;
  }
  const targets = args.slice(1).filter((arg) => !arg.startsWith("--"));
  const root = process.cwd();
  const files = targets.length === 0 ? [] : (await Promise.all(targets.map(async (target) => {
    const absolute = resolve(target);
    try {
      const entries = await readdir(absolute, { withFileTypes: true });
      return entries ? await collectFiles(target) : [absolute];
    } catch {
      return [absolute];
    }
  }))).flat();
  const findings: Finding[] = [];
  if (files.length === 0) {
    const result = scan(await readStdin(), sensitivity as Sensitivity);
    if (result.detections.length > 0) findings.push(summarize("stdin", result.detections, root));
  } else {
    for (const file of files) {
      try {
        const result = scan(await readFile(file, "utf8"), sensitivity as Sensitivity);
        if (result.detections.length > 0) findings.push(summarize(file, result.detections, root));
      } catch {
        console.error(`Unable to read ${relative(root, file)}`);
        return 2;
      }
    }
  }
  if (findings.length === 0) {
    console.log("No sensitive information detected.");
    return 0;
  }
  console.error(JSON.stringify({ findings }, null, 2));
  return 1;
}

main().then((code) => { process.exitCode = code; }).catch(() => { process.exitCode = 2; });
