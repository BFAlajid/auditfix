import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/cli/index.ts'],
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
