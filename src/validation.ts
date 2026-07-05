import { ValidationError } from './errors.js';

const DID_KEY_PATTERN = /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function requireString(body: unknown, field: string): string {
  const value = isRecord(body) ? body[field] : undefined;
  if (typeof value !== 'string' || value.length === 0) {
    throw new ValidationError(`"${field}" is required and must be a non-empty string`);
  }
  return value;
}

export function requireDidKey(body: unknown, field: string): string {
  const value = requireString(body, field);
  if (!DID_KEY_PATTERN.test(value)) {
    throw new ValidationError(`"${field}" must be a valid did:key DID`, { field, value });
  }
  return value;
}

export function optionalStringArray(body: unknown, field: string): string[] {
  const value = isRecord(body) ? body[field] : undefined;
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    throw new ValidationError(`"${field}" must be an array of strings when provided`, { field, value });
  }
  return value;
}

export function optionalPlainObject(body: unknown, field: string): Record<string, unknown> {
  const value = isRecord(body) ? body[field] : undefined;
  if (value === undefined) return {};
  if (!isRecord(value)) {
    throw new ValidationError(`"${field}" must be an object when provided`, { field, value });
  }
  return value;
}

export function requireUuidParam(params: Record<string, string>, field: string): string {
  const value = params[field];
  if (!value || !UUID_PATTERN.test(value)) {
    throw new ValidationError(`"${field}" must be a valid UUID`, { field, value });
  }
  return value;
}
