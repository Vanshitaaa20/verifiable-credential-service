import { describe, it, expect } from 'vitest';
import {
  requireString,
  requireDidKey,
  optionalStringArray,
  optionalPlainObject,
  requireUuidParam,
} from '../../src/validation.js';
import { ValidationError } from '../../src/errors.js';

describe('Phase 4: request validation', () => {
  it('requireString accepts a present non-empty string and rejects everything else', () => {
    expect(requireString({ name: 'a' }, 'name')).toBe('a');
    expect(() => requireString({}, 'name')).toThrow(ValidationError);
    expect(() => requireString({ name: '' }, 'name')).toThrow(ValidationError);
    expect(() => requireString({ name: 5 }, 'name')).toThrow(ValidationError);
    expect(() => requireString(null, 'name')).toThrow(ValidationError);
  });

  it('requireDidKey accepts a well-formed did:key and rejects other strings', () => {
    const did = 'did:key:z6MkhTtKp1jcqNy9s1nq3Wstvq13QRd5VPX724zFBEd2MJPP';
    expect(requireDidKey({ issuerDid: did }, 'issuerDid')).toBe(did);
    expect(() => requireDidKey({ issuerDid: 'did:web:example.com' }, 'issuerDid')).toThrow(ValidationError);
    expect(() => requireDidKey({ issuerDid: 'not-a-did' }, 'issuerDid')).toThrow(ValidationError);
  });

  it('optionalStringArray defaults to [] and rejects non-string-array values', () => {
    expect(optionalStringArray({}, 'type')).toEqual([]);
    expect(optionalStringArray({ type: ['A', 'B'] }, 'type')).toEqual(['A', 'B']);
    expect(() => optionalStringArray({ type: 'A' }, 'type')).toThrow(ValidationError);
    expect(() => optionalStringArray({ type: [1, 2] }, 'type')).toThrow(ValidationError);
  });

  it('optionalPlainObject defaults to {} and rejects non-object values', () => {
    expect(optionalPlainObject({}, 'claims')).toEqual({});
    expect(optionalPlainObject({ claims: { a: 1 } }, 'claims')).toEqual({ a: 1 });
    expect(() => optionalPlainObject({ claims: [1, 2] }, 'claims')).toThrow(ValidationError);
    expect(() => optionalPlainObject({ claims: 'x' }, 'claims')).toThrow(ValidationError);
  });

  it('requireUuidParam accepts a UUID and rejects malformed params', () => {
    const id = '123e4567-e89b-12d3-a456-426614174000';
    expect(requireUuidParam({ id }, 'id')).toBe(id);
    expect(() => requireUuidParam({ id: 'not-a-uuid' }, 'id')).toThrow(ValidationError);
    expect(() => requireUuidParam({}, 'id')).toThrow(ValidationError);
  });
});
