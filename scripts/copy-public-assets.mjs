import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { buildPublicAssetManifest } from "./public-asset-manifest.mjs";

const source = fileURLToPath(new URL("../src/http/public-assets/", import.meta.url));
const destination = fileURLToPath(new URL("../dist/http/public-assets/", import.meta.url));
const distHttpRoot = fileURLToPath(new URL("../dist/http/", import.meta.url));
const relativeDestination = relative(resolve(distHttpRoot), resolve(destination));

if (!relativeDestination || relativeDestination === ".." || relativeDestination.startsWith(`..${sep}`)) {
  throw new Error("Refusing to replace a public asset destination outside dist/http.");
}

await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true, force: true });

const { definitions, outputBytes } = await buildPublicAssetManifest({ sourceRoot: source });

for (const definition of definitions) {
  const bytes = outputBytes.get(definition.logicalPath);
  const logicalOutput = resolve(destination, definition.fileName);
  const versionedOutput = resolve(destination, definition.versionedFileName);

  await mkdir(dirname(logicalOutput), { recursive: true });
  await mkdir(dirname(versionedOutput), { recursive: true });
  await writeFile(logicalOutput, bytes);
  await writeFile(versionedOutput, bytes);
}
