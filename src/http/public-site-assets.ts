import { readFile } from "node:fs/promises";

import { generatedPublicAssetDefinitions } from "./public-asset-manifest.js";

export interface PublicSiteAssetResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

interface PublicAssetDefinition {
  outputFileName: string;
  contentType: string;
  immutable: boolean;
}

const immutableCacheControl = "public, max-age=31536000, immutable";
const revalidateCacheControl = "public, max-age=0, must-revalidate";
const publicAssetDefinitions = new Map<string, PublicAssetDefinition>();

for (const asset of generatedPublicAssetDefinitions) {
  publicAssetDefinitions.set(asset.logicalPath, {
    outputFileName: asset.fileName,
    contentType: asset.contentType,
    immutable: false,
  });
  publicAssetDefinitions.set(asset.versionedPath, {
    outputFileName: asset.versionedFileName,
    contentType: asset.contentType,
    immutable: true,
  });
}

export function isKnownPublicSiteAsset(pathname: string): boolean {
  return publicAssetDefinitions.has(pathname);
}

export async function readPublicSiteAsset(pathname: string): Promise<PublicSiteAssetResponse | null> {
  const definition = publicAssetDefinitions.get(pathname);

  if (!definition) {
    return null;
  }

  const assetUrl = new URL(`./public-assets/${definition.outputFileName}`, import.meta.url);
  const body = await readFile(assetUrl);

  return {
    statusCode: 200,
    headers: {
      "cache-control": definition.immutable ? immutableCacheControl : revalidateCacheControl,
      "content-type": definition.contentType,
      "x-content-type-options": "nosniff",
    },
    body,
  };
}
