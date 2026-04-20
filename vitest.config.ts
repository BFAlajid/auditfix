import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/cli/index.ts', // CLI entry point hard to unit test
        'src/**/*.generated.ts', // generated offline advisory index
        'src/types/**', // pure type declarations
      ],
      reporter: ['text', 'json-summary', 'lcov'],
      reportsDirectory: 'coverage',
      // CI fails if coverage drops below these floors. Numbers chosen to
      // match current measured coverage with a small cushion — tighten as
      // test suite grows.
      thresholds: {
        lines: 70,
        statements: 70,
        functions: 70,
        branches: 60,
      },
    },
  },
});
