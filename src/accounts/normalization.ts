const unsafeSlugCharacters = /[^a-z0-9]+/g;
const slugTrimCharacters = /^-+|-+$/g;
const basicIdPattern = /^[a-z][a-z0-9_:-]{2,127}$/;
const basicKeyPattern = /^[a-z][a-z0-9-]{1,63}$/;

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function normalizeWorkspaceSlug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(unsafeSlugCharacters, "-")
    .replace(slugTrimCharacters, "");
}

export function isValidStableId(id: string): boolean {
  return basicIdPattern.test(id);
}

export function isValidKey(key: string): boolean {
  return basicKeyPattern.test(key);
}
