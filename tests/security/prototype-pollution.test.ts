import { describe, it, expect } from 'vitest';
import { safeJsonParse } from '../../src/utils/sanitize.js';

describe('prototype pollution prevention', () => {
  it('strips __proto__ keys from parsed JSON', () => {
    const malicious = '{"__proto__": {"polluted": true}, "safe": "value"}';
    const result = safeJsonParse<Record<string, unknown>>(malicious);

    expect(result.safe).toBe('value');
    // The reviver strips the __proto__ key — verify it's not an own property
    expect(Object.prototype.hasOwnProperty.call(result, '__proto__')).toBe(false);
    // Verify Object.prototype is not polluted
    expect(({} as any).polluted).toBeUndefined();
  });

  it('strips constructor keys from parsed JSON', () => {
    const malicious = '{"constructor": {"prototype": {"injected": true}}}';
    const result = safeJsonParse<Record<string, unknown>>(malicious);

    expect(Object.prototype.hasOwnProperty.call(result, 'constructor')).toBe(false);
  });

  it('strips prototype keys from parsed JSON', () => {
    const malicious = '{"prototype": {"evil": true}}';
    const result = safeJsonParse<Record<string, unknown>>(malicious);

    expect(result.prototype).toBeUndefined();
  });

  it('strips nested __proto__ keys', () => {
    const malicious = '{"data": {"__proto__": {"polluted": true}, "value": 1}}';
    const result = safeJsonParse<{ data: { value: number } }>(malicious);

    expect(result.data.value).toBe(1);
    expect(({} as any).polluted).toBeUndefined();
  });

  it('handles normal JSON without stripping', () => {
    const normal = '{"name": "express", "version": "4.17.1"}';
    const result = safeJsonParse<{ name: string; version: string }>(normal);

    expect(result.name).toBe('express');
    expect(result.version).toBe('4.17.1');
  });

  it('strips BOM before parsing', () => {
    const withBom = '\uFEFF{"name": "test"}';
    const result = safeJsonParse<{ name: string }>(withBom);

    expect(result.name).toBe('test');
  });
});
