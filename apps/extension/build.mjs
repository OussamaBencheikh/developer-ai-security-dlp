import { build } from "esbuild";
import { cp, mkdir } from "node:fs/promises";

await mkdir("dist", { recursive: true });
for (const entry of ["background", "content", "popup", "options"]) {
  await build({
    entryPoints: [`src/${entry}.ts`],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "chrome120",
    outfile: `dist/${entry}.js`,
    sourcemap: true,
  });
}
await cp("manifest.json", "dist/manifest.json");
await cp("popup.html", "dist/popup.html");
await cp("options.html", "dist/options.html");
