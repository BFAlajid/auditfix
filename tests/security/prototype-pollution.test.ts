import { describe, it, expect } from 'vitest';
import { safeJsonParse, safeYamlParse, stripProtoKeys } from '../../src/utils/sanitize.js';

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

  describe('YAML inputs', () => {
    it('strips top-level __proto__ key from YAML', () => {
      const malicious = `
__proto__:
  admin: true
safe: value
`;
      const result = safeYamlParse(malicious) as Record<string, unknown>;

      expect(Object.prototype.hasOwnProperty.call(result, '__proto__')).toBe(false);
      expect(({} as any).admin).toBeUndefined();
      expect(result.safe).toBe('value');
    });

    it('strips nested __proto__ inside YAML mapping', () => {
      const malicious = `
packages:
  express:
    __proto__:
      polluted: true
    version: "4.17.1"
`;
      const result = safeYamlParse(malicious) as { packages: { express: { version: string } } };
      expect(result.packages.express.version).toBe('4.17.1');
      expect(Object.prototype.hasOwnProperty.call(result.packages.express, '__proto__')).toBe(false);
      expect(({} as any).polluted).toBeUndefined();
    });

    it('strips constructor / prototype keys in YAML arrays', () => {
      const malicious = `
entries:
  - name: foo
    constructor:
      prototype:
        injected: true
  - name: bar
    prototype:
      evil: true
`;
      const result = safeYamlParse(malicious) as { entries: Record<string, unknown>[] };
      expect(result.entries).toHaveLength(2);
      expect(Object.prototype.hasOwnProperty.call(result.entries[0], 'constructor')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(result.entries[1], 'prototype')).toBe(false);
      expect(({} as any).injected).toBeUndefined();
      expect(({} as any).evil).toBeUndefined();
    });

    it('leaves benign YAML keys untouched', () => {
      const safe = `
name: my-pkg
version: 1.2.3
deps:
  - react
  - vue
`;
      const result = safeYamlParse(safe) as { name: string; version: string; deps: string[] };
      expect(result.name).toBe('my-pkg');
      expect(result.version).toBe('1.2.3');
      expect(result.deps).toEqual(['react', 'vue']);
    });
  });

  describe('stripProtoKeys helper', () => {
    it('strips dangerous keys in place from an arbitrary object graph', () => {
      const obj: any = {
        a: 1,
        __proto__: { bad: true },
        child: { __proto__: { alsoBad: true }, b: 2 },
        list: [{ constructor: { evil: true }, ok: 3 }],
      };
      stripProtoKeys(obj);
      expect(Object.prototype.hasOwnProperty.call(obj, '__proto__')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(obj.child, '__proto__')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(obj.list[0], 'constructor')).toBe(false);
      expect(obj.a).toBe(1);
      expect(obj.child.b).toBe(2);
      expect(obj.list[0].ok).toBe(3);
    });

    it('handles primitives, null, and undefined without throwing', () => {
      expect(stripProtoKeys(null)).toBeNull();
      expect(stripProtoKeys(undefined)).toBeUndefined();
      expect(stripProtoKeys(42)).toBe(42);
      expect(stripProtoKeys('hello')).toBe('hello');
    });

    it('is safe against circular references', () => {
      const a: any = { name: 'a' };
      const b: any = { name: 'b', __proto__: { bad: true } };
      a.peer = b;
      b.peer = a;
      expect(() => stripProtoKeys(a)).not.toThrow();
      expect(Object.prototype.hasOwnProperty.call(b, '__proto__')).toBe(false);
    });
  });
});
