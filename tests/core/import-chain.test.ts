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

  it('detects require() calls', () => {
    setup({
      'src/app.js': `const axios = require('axios');\nconst fs = require('fs');`,
    });
    const result = scanImportChains(tmpDir);
    cleanup();

    expect(result.has('axios')).toBe(true);
    expect(result.has('fs')).toBe(true);
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

  it('isDirectlyImported returns correct values', () => {
    const packages = new Set(['express', 'lodash']);
    expect(isDirectlyImported('express', packages)).toBe(true);
    expect(isDirectlyImported('axios', packages)).toBe(false);
  });
});
