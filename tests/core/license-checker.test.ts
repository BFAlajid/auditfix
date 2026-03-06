import { describe, it, expect } from 'vitest';
import { scanLicenses } from '../../src/core/scanner/license-checker.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeNode(name: string, version: string, isProd = true): DependencyNode {
  return {
    name, version, resolved: '', integrity: '',
    dependencies: [], isProduction: isProd, isDev: !isProd,
    isOptional: false, depth: 1, dependencyPath: [],
  };
}

describe('License scanner', () => {
  let tmpDir: string;

  function setupPkg(name: string, license: string) {
    const pkgDir = path.join(tmpDir, 'node_modules', name);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name, license }));
  }

  function setup() {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditfix-license-'));
  }

  function cleanup() {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  it('flags GPL-3.0 as copyleft', () => {
    setup();
    setupPkg('gpl-pkg', 'GPL-3.0');
    const graph: DependencyGraph = new Map();
    graph.set('gpl-pkg@1.0.0', makeNode('gpl-pkg', '1.0.0'));

    const findings = scanLicenses(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('copyleft');
    expect(findings[0].license).toBe('GPL-3.0');
  });

  it('flags AGPL-3.0 as network-copyleft', () => {
    setup();
    setupPkg('agpl-pkg', 'AGPL-3.0');
    const graph: DependencyGraph = new Map();
    graph.set('agpl-pkg@1.0.0', makeNode('agpl-pkg', '1.0.0'));

    const findings = scanLicenses(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('network-copyleft');
  });

  it('does not flag MIT', () => {
    setup();
    setupPkg('safe-pkg', 'MIT');
    const graph: DependencyGraph = new Map();
    graph.set('safe-pkg@1.0.0', makeNode('safe-pkg', '1.0.0'));

    const findings = scanLicenses(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(0);
  });

  it('handles OR expressions — permissive option makes it OK', () => {
    setup();
    setupPkg('dual-pkg', '(MIT OR GPL-3.0)');
    const graph: DependencyGraph = new Map();
    graph.set('dual-pkg@1.0.0', makeNode('dual-pkg', '1.0.0'));

    const findings = scanLicenses(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(0); // MIT option is permissive
  });

  it('reports production status correctly', () => {
    setup();
    setupPkg('dev-gpl', 'GPL-3.0');
    const graph: DependencyGraph = new Map();
    graph.set('dev-gpl@1.0.0', makeNode('dev-gpl', '1.0.0', false));

    const findings = scanLicenses(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(1);
    expect(findings[0].isProduction).toBe(false);
  });
});
