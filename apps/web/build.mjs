import { build } from "esbuild";
import { cp, mkdir } from "node:fs/promises";
await mkdir("dist", { recursive: true });
await build({ entryPoints: ["src/main.ts"], bundle: true, format: "iife", platform: "browser", target: "es2022", outfile: "dist/main.js", sourcemap: true });
await cp("src/index.html", "dist/index.html");
await cp("src/styles.css", "dist/styles.css");
