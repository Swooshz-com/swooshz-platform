import { cp, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(new URL("../src/http/public-assets/", import.meta.url));
const destination = fileURLToPath(new URL("../dist/http/public-assets/", import.meta.url));

await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true, force: true });
