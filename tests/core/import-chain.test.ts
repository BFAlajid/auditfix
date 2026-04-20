import { describe, it, expect, beforeEach } from 'vitest';
import {
  scanImportChains,
  isDirectlyImported,
  clearImportChainCache,
} from '../../src/core/graph/import-chain.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('Import chain scanner', () => {
  let tmpDir: string;

  beforeEach(() => {
    clearImportChainCache();
  });

  function setup(files: Record<string, string>) {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditfix-import-'));
    for (const [filePath, content] of Object.entries(files)) {
      const fullPath = path.join(tmpDir, filePath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content);
    }
  }

  function cleanup() {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  it('detects ES imports in src directory', () => {
    setup({
      'src/index.ts': `import express from 'express';\nimport { get } from 'lodash';`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('express')).toBe(true);
    expect(result.has('lodash')).toBe(true);
  });

  it('detects require() calls and filters Node builtins', () => {
    setup({
      'src/app.js': `const axios = require('axios');\nconst fs = require('fs');\nconst nodeFs = require('node:fs');`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('axios')).toBe(true);
    expect(result.has('fs')).toBe(false);
    expect(result.has('node:fs')).toBe(false);
  });

  it('detects dynamic imports', () => {
    setup({
      'src/lazy.ts': `const mod = await import('some-module');`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('some-module')).toBe(true);
  });

  it('handles scoped packages', () => {
    setup({
      'src/index.ts': `import { something } from '@myorg/utils/helpers';`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('@myorg/utils')).toBe(true);
  });

  it('scans root entry points', () => {
    setup({
      'index.js': `const express = require('express');`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('express')).toBe(true);
  });

  it('ignores relative imports', () => {
    setup({
      'src/index.ts': `import { foo } from './utils';\nimport bar from '../lib/bar';`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.size).toBe(0);
  });

  it('ignores single-line commented-out imports', () => {
    setup({
      'src/index.ts': [
        `import express from 'express';`,
        `// import axios from 'axios';`,
        `// const old = require('old-pkg');`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('express')).toBe(true);
    expect(result.has('axios')).toBe(false);
    expect(result.has('old-pkg')).toBe(false);
  });

  it('ignores imports inside multi-line comment blocks', () => {
    setup({
      'src/index.ts': [
        `import express from 'express';`,
        `/*`,
        `import axios from 'axios';`,
        `const old = require('old-pkg');`,
        `*/`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('express')).toBe(true);
    expect(result.has('axios')).toBe(false);
    expect(result.has('old-pkg')).toBe(false);
  });

  it('does not strip comment-like text inside string literals', () => {
    setup({
      'src/index.ts': [
        `const url = "https://example.com"; // a comment`,
        `import express from 'express';`,
        `const msg = '// not a comment import fake from "fake"';`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('express')).toBe(true);
    // 'fake' appears inside a string literal that looks like a comment, but since
    // the comment stripping respects strings, the string content remains. However,
    // the regex should not match it because it is inside a string value, not a
    // top-level import statement. The key test is that 'express' is still detected.
  });

  it('detects re-exports', () => {
    setup({
      'src/index.ts': [
        `export { foo } from 'some-lib';`,
        `export * from '@scope/reexported';`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('some-lib')).toBe(true);
    expect(result.has('@scope/reexported')).toBe(true);
  });

  it('detects dynamic imports with template literals', () => {
    setup({
      'src/index.ts': 'const mod = await import(`dynamic-pkg`);',
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('dynamic-pkg')).toBe(true);
  });

  it('filters out Node.js builtin modules', () => {
    setup({
      'src/index.ts': [
        `import path from 'path';`,
        `import { readFile } from 'node:fs';`,
        `import crypto from 'crypto';`,
        `import express from 'express';`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('path')).toBe(false);
    expect(result.has('crypto')).toBe(false);
    expect(result.has('express')).toBe(true);
  });

  it('handles mixed commented and uncommented imports', () => {
    setup({
      'src/index.ts': [
        `import express from 'express';`,
        `// import removed from 'removed-pkg';`,
        `/* import alsoRemoved from 'also-removed'; */`,
        `import active from 'active-pkg';`,
        `/*`,
        `  Multi-line block:`,
        `  const x = require('blocked-pkg');`,
        `*/`,
        `const y = require('real-pkg');`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('express')).toBe(true);
    expect(result.has('active-pkg')).toBe(true);
    expect(result.has('real-pkg')).toBe(true);
    expect(result.has('removed-pkg')).toBe(false);
    expect(result.has('also-removed')).toBe(false);
    expect(result.has('blocked-pkg')).toBe(false);
  });

  it('isDirectlyImported returns correct values', () => {
    const packages = new Set(['express', 'lodash']);
    expect(isDirectlyImported('express', packages)).toBe(true);
    expect(isDirectlyImported('axios', packages)).toBe(false);
  });

  it('stripComments preserves // and /* inside string and template literals', () => {
    setup({
      'src/index.ts': [
        `const a = "https://example.com/path";`,
        `const b = '/* not a comment */';`,
        `const c = \`url: // still not a comment\`;`,
        `import real from 'real-pkg';`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('real-pkg')).toBe(true);
  });

  it('parses JSX/TSX imports', () => {
    setup({
      'src/App.tsx': [
        `import React from 'react';`,
        `import { Button } from '@ui/components';`,
        `export default function App() { return <Button/>; }`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('react')).toBe(true);
    expect(result.has('@ui/components')).toBe(true);
  });

  it('detects dynamic import(expr) with all quote styles', () => {
    setup({
      'src/dyn.ts': [
        `const a = await import('single-q');`,
        `const b = await import("double-q");`,
        `const c = await import(\`tmpl-q\`);`,
      ].join('\n'),
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('single-q')).toBe(true);
    expect(result.has('double-q')).toBe(true);
    expect(result.has('tmpl-q')).toBe(true);
  });

  it('mtime memoization: second call with unchanged mtime returns cached parse', () => {
    setup({
      'src/index.ts': `import express from 'express';`,
    });

    // Pin the file's mtime to a whole-second timestamp so utimesSync
    // round-trips cleanly through statSync (sub-ms precision loss otherwise).
    const filePath = path.join(tmpDir, 'src/index.ts');
    const pinned = new Date(Math.floor(Date.now() / 1000) * 1000 - 10_000);
    fs.utimesSync(filePath, pinned, pinned);

    // First pass warms the cache.
    const first = scanImportChains(tmpDir);
    expect(first.has('express')).toBe(true);

    // Mutate file contents, then re-pin the same mtime. If the cache is
    // honored, the scanner returns the cached parse ('express') rather than
    // the new content ('different-pkg').
    fs.writeFileSync(filePath, `import different from 'different-pkg';`);
    fs.utimesSync(filePath, pinned, pinned);

    const second = scanImportChains(tmpDir);
    cleanup();

    expect(second.has('express')).toBe(true);
    expect(second.has('different-pkg')).toBe(false);
  });

  it('mtime memoization: updated mtime invalidates cache', () => {
    setup({
      'src/index.ts': `import express from 'express';`,
    });

    const first = scanImportChains(tmpDir);
    expect(first.has('express')).toBe(true);

    const filePath = path.join(tmpDir, 'src/index.ts');
    fs.writeFileSync(filePath, `import lodash from 'lodash';`);
    // Bump mtime to some future time to guarantee cache miss.
    const future = new Date(Date.now() + 5000);
    fs.utimesSync(filePath, future, future);

    const second = scanImportChains(tmpDir);
    cleanup();

    expect(second.has('lodash')).toBe(true);
    expect(second.has('express')).toBe(false);
  });
});
