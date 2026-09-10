import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

if (!existsSync("apps/cli/dist/index.js")) {
  execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build", "-w", "@dlp/cli"], { stdio: "inherit" });
}

const stagedFiles = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], { encoding: "utf8" })
  .split(/\r?\n/)
  .filter(Boolean);
if (stagedFiles.length === 0) process.exit(0);

const result = spawnSync(process.execPath, ["apps/cli/dist/index.js", "scan", ...stagedFiles], { encoding: "utf8" });
process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");
process.exitCode = result.status ?? 2;