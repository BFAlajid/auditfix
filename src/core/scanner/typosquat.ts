/**
 * Typosquatting detection.
 * Compares dependency names against a list of popular npm packages
 * using Levenshtein distance and common substitution patterns.
 */
import type { DependencyGraph } from '../../types/package.js';

export type TyposquatFinding = {
  package: string;
  version: string;
  similarTo: string;
  distance: number;
  reason: string;
  isProduction: boolean;
};

/** Top 100 most popular npm packages (curated) */
const POPULAR_PACKAGES = new Set([
  'lodash', 'chalk', 'react', 'express', 'commander', 'debug', 'glob',
  'async', 'bluebird', 'moment', 'request', 'underscore', 'uuid',
  'mkdirp', 'minimist', 'semver', 'colors', 'yargs', 'inquirer',
  'axios', 'webpack', 'babel-core', 'typescript', 'eslint', 'prettier',
  'jest', 'mocha', 'chai', 'sinon', 'supertest', 'nodemon', 'dotenv',
  'cors', 'body-parser', 'mongoose', 'sequelize', 'pg', 'mysql2',
  'redis', 'jsonwebtoken', 'bcrypt', 'passport', 'socket.io', 'ws',
  'cheerio', 'puppeteer', 'sharp', 'multer', 'helmet', 'morgan',
  'compression', 'cookie-parser', 'node-fetch', 'got', 'superagent',
  'rxjs', 'ramda', 'immutable', 'classnames', 'prop-types',
  'react-dom', 'react-router', 'redux', 'mobx', 'vue', 'angular',
  'next', 'nuxt', 'gatsby', 'svelte', 'preact', 'lit',
  'tslib', 'core-js', 'regenerator-runtime', 'whatwg-fetch',
  'postcss', 'autoprefixer', 'sass', 'less', 'tailwindcss',
  'esbuild', 'rollup', 'vite', 'turbo', 'nx', 'lerna',
  'aws-sdk', 'firebase', 'stripe', 'twilio', 'nodemailer',
  'winston', 'pino', 'bunyan', 'log4js', 'chalk',
  'rimraf', 'fs-extra', 'shelljs', 'cross-env', 'concurrently',
  'husky', 'lint-staged', 'commitlint', 'standard-version',
  'qs', 'tough-cookie', 'form-data', 'http-proxy', 'http-proxy-middleware',
]);

/** Common character substitutions used in typosquatting */
const SUBSTITUTIONS: [string, string][] = [
  ['0', 'o'], ['1', 'l'], ['1', 'i'], ['5', 's'],
  ['rn', 'm'], ['vv', 'w'], ['cl', 'd'],
];

/**
 * Scan dependency graph for potential typosquat packages.
 */
export function detectTyposquats(graph: DependencyGraph): TyposquatFinding[] {
  const findings: TyposquatFinding[] = [];
  const checked = new Set<string>();
  const popularList = [...POPULAR_PACKAGES];

  for (const [, node] of graph) {
    if (checked.has(node.name)) continue;
    checked.add(node.name);

    // Skip if this IS a popular package
    if (POPULAR_PACKAGES.has(node.name)) continue;

    for (const popular of popularList) {
      // Skip if same package or very different length
      if (Math.abs(node.name.length - popular.length) > 2) continue;

      const dist = levenshtein(node.name, popular);

      if (dist === 1) {
        findings.push({
          package: node.name,
          version: node.version,
          similarTo: popular,
          distance: dist,
          reason: `Name differs by 1 character from popular package "${popular}"`,
          isProduction: node.isProduction,
        });
        break; // One match is enough
      }

      // Check common substitutions
      if (dist <= 2) {
        const subMatch = checkSubstitutions(node.name, popular);
        if (subMatch) {
          findings.push({
            package: node.name,
            version: node.version,
            similarTo: popular,
            distance: dist,
            reason: subMatch,
            isProduction: node.isProduction,
          });
          break;
        }
      }
    }

    // Check for scope-stripping: popular scoped package used without scope
    // e.g., "types-node" instead of "@types/node"
    for (const popular of popularList) {
      if (popular.startsWith('@') && node.name === popular.replace('@', '').replace('/', '-')) {
        findings.push({
          package: node.name,
          version: node.version,
          similarTo: popular,
          distance: 0,
          reason: `Looks like unscoped version of "${popular}" (potential confusion attack)`,
          isProduction: node.isProduction,
        });
        break;
      }
    }
  }

  return findings;
}

function checkSubstitutions(name: string, popular: string): string | null {
  for (const [from, to] of SUBSTITUTIONS) {
    if (name.includes(from) && name.replace(from, to) === popular) {
      return `Contains "${from}" which could be a substitution for "${to}" in "${popular}"`;
    }
    if (name.includes(to) && name.replace(to, from) === popular) {
      return `Contains "${to}" which could be a substitution for "${from}" in "${popular}"`;
    }
  }
  return null;
}

/** Levenshtein distance between two strings */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }

  return dp[m][n];
}
