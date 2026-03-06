/**
 * auditfix CLI entry point.
 * Commander-based arg parsing with exitOverride for testing.
 */
import { Command, Option } from 'commander';
import { existsSync, statSync } from 'node:fs';
import { analyze } from '../core/analyzer.js';
import { loadConfig } from '../core/config.js';
import { renderTerminalReport, getExitCode } from './output/terminal.js';
import { renderJsonReport } from './output/json.js';
import { renderSarifReport } from './output/sarif.js';
import { addToAllowList } from '../core/allowlist/local.js';
import { planFixes } from '../core/fixer/safe-update.js';
import { applyFixes } from '../core/fixer/lockfile-writer.js';
import { detectAndParseLockfile } from '../core/lockfile/parser.js';
import { isValidAdvisoryId } from '../utils/sanitize.js';
import { setLogLevel } from '../utils/logger.js';
import * as logger from '../utils/logger.js';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { join } from 'node:path';
import { safeJsonParse } from '../utils/sanitize.js';
import chalk from 'chalk';

const VERSION = process.env.AUDITFIX_VERSION ?? '1.0.1';

const SEVERITY_CHOICES = ['critical', 'high', 'medium', 'low', 'info'];

export function createProgram(): Command {
const program = new Command();

program
  .name('auditfix')
  .description('Smarter npm dependency security CLI — production reachability, actionable fixes, noise-free reports')
  .version(VERSION)
  .option('--prod-only', 'Only show production vulnerabilities', false)
  .addOption(new Option('--severity <level>', 'Minimum severity threshold').choices(SEVERITY_CHOICES))
  .option('--fix', 'Auto-fix safe (non-breaking) updates', false)
  .option('--json', 'Output as JSON', false)
  .option('--sarif', 'Output as SARIF v2.1.0 JSON (for GitHub Code Scanning)', false)
  .option('--verbose', 'Enable debug logging', false)
  .option('--dir <path>', 'Project directory to scan', process.cwd())
  .option('-w, --workspace <name>', 'Filter results to a specific workspace (monorepo)')
  .action(async (options) => {
    if (options.verbose) {
      setLogLevel('debug');
    }

    // H1: Validate --dir exists and is a directory
    const dir = path.resolve(options.dir);
    if (!existsSync(dir) || !statSync(dir).isDirectory()) {
      logger.error(`--dir path does not exist or is not a directory: ${options.dir}`);
      process.exit(2);
    }
    options.dir = dir;

    try {
      // Build CLI overrides from explicitly-set flags only.
      // Only include values the user actually passed on the command line
      // so that config file values are not clobbered by Commander defaults.
      const cliOverrides: Record<string, unknown> = {};
      if (options.prodOnly === true) {
        cliOverrides.productionOnly = true;
      }
      if (options.severity !== undefined) {
        cliOverrides.severity = options.severity;
      }
      if (options.json === true) {
        cliOverrides.output = 'json' as const;
      }
      if (options.sarif === true) {
        cliOverrides.output = 'sarif' as const;
      }

      const config = await loadConfig(cliOverrides, options.dir);

      const report = await analyze({
        projectDir: options.dir,
        productionOnly: config.productionOnly,
        severityThreshold: config.severity,
        workspace: options.workspace,
      });

      if (config.output === 'sarif') {
        console.log(renderSarifReport(report, VERSION));
      } else if (config.output === 'json') {
        console.log(renderJsonReport(report));
      } else {
        console.log(renderTerminalReport(report, VERSION));
      }

      // Apply fixes if requested
      if (options.fix && report.vulnerabilities.length > 0) {
        console.log('');
        await runFix(options.dir, report);
      }

      const exitCode = getExitCode(report);
      process.exit(exitCode);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(message);
      process.exit(2);
    }
  });

program
  .command('ignore <advisory-id>')
  .description('Add a vulnerability to the project allow-list (.auditfixignore)')
  .requiredOption('--package <name>', 'Package name the advisory applies to')
  .requiredOption('--reason <text>', 'Reason for ignoring (required for audit trail)')
  .option('--expires <date>', 'Expiry date (YYYY-MM-DD)', getDefaultExpiry())
  .option('--dir <path>', 'Project directory', process.cwd())
  .action((advisoryId: string, options) => {
    if (!isValidAdvisoryId(advisoryId)) {
      logger.error(`Invalid advisory ID: ${advisoryId}. Expected format: GHSA-xxxx-yyyy-zzzz or CVE-YYYY-NNNNN`);
      process.exit(2);
    }

    const expiryDate = new Date(options.expires);
    if (isNaN(expiryDate.getTime())) {
      logger.error(`Invalid expiry date: ${options.expires}. Use YYYY-MM-DD format.`);
      process.exit(2);
    }

    if (expiryDate < new Date()) {
      logger.error(`Expiry date ${options.expires} is in the past.`);
      process.exit(2);
    }

    addToAllowList(options.dir, {
      id: advisoryId,
      package: options.package,
      reason: options.reason,
      expires: options.expires,
    });

    console.log(`Added ${advisoryId} (${options.package}) to .auditfixignore — expires ${options.expires}`);
  });

async function runFix(projectDir: string, report: import('../types/report.js').AuditReport): Promise<void> {
  // Read package.json to get declared dependency ranges
  let packageJsonDeps: Record<string, string> = {};
  try {
    const pkgContent = readFileSync(join(projectDir, 'package.json'), 'utf-8');
    const pkg = safeJsonParse<Record<string, Record<string, string>>>(pkgContent);
    packageJsonDeps = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
    };
  } catch {
    logger.warn('Could not read package.json for fix analysis');
    return;
  }

  // Parse lockfile to get dependency graph
  let graph: import('../types/package.js').DependencyGraph;
  let lockfileType: import('../types/package.js').LockfileType | undefined;
  try {
    const lockfileResult = detectAndParseLockfile(projectDir);
    graph = lockfileResult.graph;
    lockfileType = lockfileResult.type;
  } catch {
    logger.warn('Could not parse lockfile for fix analysis');
    return;
  }

  const plan = planFixes(report.vulnerabilities, graph, packageJsonDeps);

  if (plan.safe.length === 0) {
    console.log(chalk.yellow('No safe auto-fixes available.'));
    if (plan.breaking.length > 0) {
      console.log(chalk.dim(`${plan.breaking.length} fixes require breaking changes (manual review needed):`));
      for (const b of plan.breaking) {
        console.log(chalk.dim(`  ${b.packageName} ${b.currentVersion} → ${b.fixVersion}: ${b.reason}`));
      }
    }
    if (plan.noFix.length > 0) {
      console.log(chalk.dim(`${plan.noFix.length} vulnerabilities have no fix available.`));
    }
    return;
  }

  console.log(chalk.bold(`Applying ${plan.safe.length} safe fixes...`));
  for (const s of plan.safe) {
    console.log(`  ${s.packageName} ${s.currentVersion} → ${chalk.green(s.fixVersion)}`);
  }

  const result = await applyFixes(projectDir, plan.safe, lockfileType);

  if (result.applied.length > 0) {
    console.log(chalk.green(`\nFixed ${result.applied.length} vulnerabilities.`));
    console.log(chalk.dim('Run your package manager install to update node_modules.'));
  }

  if (result.failed.length > 0) {
    console.log(chalk.red(`\n${result.failed.length} fixes failed:`));
    for (const f of result.failed) {
      console.log(chalk.red(`  ${f.packageName}: ${f.reason}`));
    }
  }

  if (plan.breaking.length > 0) {
    console.log(chalk.yellow(`\n${plan.breaking.length} fixes require manual review:`));
    for (const b of plan.breaking) {
      console.log(chalk.dim(`  ${b.packageName} ${b.currentVersion} → ${b.fixVersion}: ${b.reason}`));
    }
  }
}

function getDefaultExpiry(): string {
  const date = new Date();
  date.setFullYear(date.getFullYear() + 1);
  return date.toISOString().split('T')[0];
}

return program;
}

// Auto-parse when run as CLI entry point
createProgram().parse();
