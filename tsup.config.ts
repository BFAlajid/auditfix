import { defineConfig } from 'tsup';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));

// Two builds:
//   - CLI entry (dist/index.js): shebang banner, inline sourcemaps so they
//     ship in the tarball without a separate .map file that npm users'd
//     find confusing.
//   - Action entry (dist/action/index.js): bundled for GitHub Actions
//     (node20 runtime), no shebang, external sourcemap is fine because
//     Actions log references line numbers of the bundled file directly.
export default defineConfig([
  {
    entry: { index: 'src/cli/index.ts' },
    define: {
      'process.env.AUDITFIX_VERSION': JSON.stringify(pkg.version),
    },
    format: ['esm'],
    target: 'node18',
    clean: true,
    shims: false,
    banner: { js: '#!/usr/bin/env node' },
    outDir: 'dist',
    splitting: false,
    // Inline maps so npm consumers don't see orphan .map files.
    sourcemap: 'inline',
  },
  {
    entry: { 'action/index': 'action/index.ts' },
    define: {
      'process.env.AUDITFIX_VERSION': JSON.stringify(pkg.version),
    },
    format: ['esm'],
    target: 'node20',
    // Do NOT clean here — would wipe the CLI build above.
    clean: false,
    shims: false,
    outDir: 'dist',
    // The action bundle must be fully self-contained (node_modules
    // isn't available at Action runtime).
    noExternal: [/.*/],
    splitting: false,
    sourcemap: true,
  },
]);
