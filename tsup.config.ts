import { defineConfig } from 'tsup';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));

export default defineConfig({
  entry: ['src/cli/index.ts'],
  define: {
    'process.env.AUDITFIX_VERSION': JSON.stringify(pkg.version),
  },
  format: ['esm'],
  target: 'node18',
  clean: true,
  shims: false,
  banner: {
    js: '#!/usr/bin/env node',
  },
  outDir: 'dist',
  splitting: false,
  sourcemap: true,
});
