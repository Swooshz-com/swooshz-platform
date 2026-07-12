import { readFile } from "node:fs/promises";

export interface PublicSiteAssetResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

interface PublicAssetDefinition {
  fileName: string;
  contentType: string;
}

const publicAssetDefinitions = new Map<string, PublicAssetDefinition>([
  ["/public-assets/public-site.css", { fileName: "public-site.css", contentType: "text/css; charset=utf-8" }],
  ["/public-assets/public-site.js", { fileName: "public-site.js", contentType: "text/javascript; charset=utf-8" }],
  ["/public-assets/swooshz-mark.png", { fileName: "swooshz-mark.png", contentType: "image/png" }],
  ["/public-assets/hero-monument-640.avif", { fileName: "hero-monument-640.avif", contentType: "image/avif" }],
  ["/public-assets/hero-monument-960.avif", { fileName: "hero-monument-960.avif", contentType: "image/avif" }],
  ["/public-assets/hero-monument-1280.avif", { fileName: "hero-monument-1280.avif", contentType: "image/avif" }],
  ["/public-assets/hero-monument-1672.avif", { fileName: "hero-monument-1672.avif", contentType: "image/avif" }],
  ["/public-assets/hero-monument-640.webp", { fileName: "hero-monument-640.webp", contentType: "image/webp" }],
  ["/public-assets/hero-monument-960.webp", { fileName: "hero-monument-960.webp", contentType: "image/webp" }],
  ["/public-assets/hero-monument-1280.webp", { fileName: "hero-monument-1280.webp", contentType: "image/webp" }],
  ["/public-assets/hero-monument-1672.webp", { fileName: "hero-monument-1672.webp", contentType: "image/webp" }],
  ["/public-assets/hero-monument-640.png", { fileName: "hero-monument-640.png", contentType: "image/png" }],
  ["/public-assets/hero-monument-1280.png", { fileName: "hero-monument-1280.png", contentType: "image/png" }],
  ["/public-assets/fonts/manrope-latin-variable.woff2", { fileName: "fonts/manrope-latin-variable.woff2", contentType: "font/woff2" }],
  ["/public-assets/fonts/fraunces-italic-latin-variable.woff2", { fileName: "fonts/fraunces-italic-latin-variable.woff2", contentType: "font/woff2" }],
]);

export function isKnownPublicSiteAsset(pathname: string): boolean {
  return publicAssetDefinitions.has(pathname);
}

export async function readPublicSiteAsset(pathname: string): Promise<PublicSiteAssetResponse | null> {
  const definition = publicAssetDefinitions.get(pathname);

  if (!definition) {
    return null;
  }

  const assetUrl = new URL(`./public-assets/${definition.fileName}`, import.meta.url);
  const body = await readFile(assetUrl);

  return {
    statusCode: 200,
    headers: {
      "cache-control": "public, max-age=31536000, immutable",
      "content-type": definition.contentType,
      "x-content-type-options": "nosniff",
    },
    body,
  };
}
