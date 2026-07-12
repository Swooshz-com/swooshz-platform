import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { buildPublicAssetManifest } from "./public-asset-manifest.mjs";

const outputPath = fileURLToPath(new URL("../src/http/public-asset-manifest.ts", import.meta.url));
const checkOnly = process.argv.includes("--check");
const { source } = await buildPublicAssetManifest();

if (checkOnly) {
  const current = await readFile(outputPath, "utf8").catch(() => "");

  if (current.replaceAll("\r\n", "\n") !== source) {
    console.error("Generated public asset manifest is stale. Run npm run build and commit the result.");
    process.exitCode = 1;
  }
} else {
  await writeFile(outputPath, source, "utf8");
}
