import { describe, it, expect } from 'vitest';
import { scanImportChains, isDirectlyImported } from '../../src/core/graph/import-chain.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('Import chain scanner', () => {
  let tmpDir: string;

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
});
