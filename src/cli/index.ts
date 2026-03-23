/**
 * auditfix CLI entry point.
 * Commander-based arg parsing with exitOverride for testing.
 */
import { Command, Option } from 'commander';
import { existsSync, statSync } from 'node:fs';
import type { AuditReport } from '../types/report.js';
import { analyze } from '../core/analyzer.js';
import { loadConfig } from '../core/config.js';
import { renderTerminalReport, getExitCode, getExitCodeForStrategy } from './output/terminal.js';
import { renderJsonReport } from './output/json.js';
import { renderSarifReport, renderSarifDiffReport } from './output/sarif.js';
import { generateSbom } from './output/sbom.js';
import { addToAllowList } from '../core/allowlist/local.js';
import { planFixes } from '../core/fixer/safe-update.js';
import { applyFixes } from '../core/fixer/lockfile-writer.js';
import { generateRemediationPlan } from '../core/fixer/remediation.js';
import { createFixPr } from '../core/fixer/pr-creator.js';
import { detectAndParseLockfile } from '../core/lockfile/parser.js';
import { scanInstallScripts } from '../core/scanner/install-scripts.js';
import { scanLicenses } from '../core/scanner/license-checker.js';
import { sendWebhook } from '../core/notify/webhook.js';
import { postPrComment } from '../core/notify/pr-comment.js';
import { checkDepAge } from '../core/scanner/dep-age.js';
import { detectTyposquats } from '../core/scanner/typosquat.js';
import { checkProvenance } from '../core/scanner/provenance.js';
import { scanBehavior } from '../core/scanner/behavior.js';
import { generateVex } from './output/vex.js';
import { loadPolicy } from '../core/policy/loader.js';
import { evaluatePolicy } from '../core/policy/evaluator.js';
import { aggregateFindings } from '../core/policy/findings.js';
import { diffReports } from '../core/diff.js';
import { isValidAdvisoryId } from '../utils/sanitize.js';
import { setLogLevel } from '../utils/logger.js';
import * as logger from '../utils/logger.js';
import { readFileSync, watch as fsWatch } from 'node:fs';
import * as path from 'node:path';
import { join } from 'node:path';
import { safeJsonParse } from '../utils/sanitize.js';
import chalk from 'chalk';

const VERSION = process.env.AUDITFIX_VERSION ?? '2.0.0';

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
  .option('--sbom', 'Generate CycloneDX 1.5 SBOM (JSON)', false)
  .option('--scan-scripts', 'Scan for suspicious install scripts', false)
  .option('--remediate', 'Show guided remediation plan', false)
  .option('--create-pr', 'Create a GitHub PR with fixes (requires gh CLI)', false)
  .option('--ci', 'CI mode: no colors, minimal output, strict exit codes', false)
  .addOption(new Option('--fail-on <strategy>', 'CI exit code strategy').choices(['production-critical', 'production-high', 'any']))
  .option('--check-licenses', 'Scan dependencies for copyleft/problematic licenses', false)
  .option('--check-deps-age', 'Flag packages with no updates in 2+ years', false)
  .option('--check-typosquats', 'Detect potential typosquatting packages', false)
  .option('--check-provenance', 'Check npm package provenance attestations', false)
  .option('--scan-behavior', 'Deep scan package source for suspicious behavior patterns', false)
  .option('--vex', 'Generate OpenVEX document from scan results', false)
  .option('--sarif-baseline <path>', 'SARIF diff mode: only output NEW vulns not in baseline JSON report')
  .option('--pr-comment', 'Post scan results as a GitHub PR comment (requires GITHUB_TOKEN)', false)
  .option('--policy <path>', 'Path to policy file (auto-detects .auditfix-policy.yml)')
  .option('--no-policy', 'Skip policy evaluation')
  .option('--no-cache', 'Bypass advisory cache')
  .option('--webhook <url>', 'Send results to a webhook URL (Slack or generic)')
  .option('--watch', 'Watch lockfile for changes and re-scan', false)
  .option('--verbose', 'Enable debug logging', false)
  .option('--dir <path>', 'Project directory to scan', process.cwd())
  .option('-w, --workspace <name>', 'Filter results to a specific workspace (monorepo)')
  .action(async (options) => {
    if (options.verbose) {
      setLogLevel('debug');
    }

    // CI mode: disable colors, force JSON output
    if (options.ci) {
      chalk.level = 0;
    }

    // H1: Validate --dir exists and is a directory
    const dir = path.resolve(options.dir);
    if (!existsSync(dir) || !statSync(dir).isDirectory()) {
      logger.error(`--dir path does not exist or is not a directory: ${options.dir}`);
      process.exit(2);
    }
    options.dir = dir;

    // --watch mode: watch lockfiles and re-scan
    if (options.watch) {
      console.log(chalk.bold('Watch mode: monitoring lockfiles for changes...'));
      const lockfiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
      let scanning = false;
      const runScan = async () => {
        if (scanning) return;
        scanning = true;
        console.log(chalk.dim(`\n[${new Date().toLocaleTimeString()}] Lockfile changed, re-scanning...`));
        try {
          const config = await loadConfig({}, options.dir);
          const report = await analyze({
            projectDir: options.dir,
            productionOnly: config.productionOnly,
            severityThreshold: config.severity,
          });
          console.log(renderTerminalReport(report, VERSION));
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          logger.error(msg);
        }
        scanning = false;
      };
      // Initial scan
      await runScan();
      // Watch for changes
      for (const lockfile of lockfiles) {
        const lockPath = join(options.dir, lockfile);
        if (existsSync(lockPath)) {
          fsWatch(lockPath, { persistent: true }, () => { runScan(); });
          logger.info(`Watching ${lockfile}`);
        }
      }
      // Keep process alive
      return;
    }

    try {
      // --sbom: generate CycloneDX SBOM and exit (no audit needed)
      if (options.sbom) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        let projectName: string | undefined;
        try {
          const pkg = safeJsonParse<Record<string, string>>(readFileSync(join(options.dir, 'package.json'), 'utf-8'));
          projectName = pkg.name;
        } catch { /* optional */ }
        console.log(generateSbom(lockfileResult.graph, VERSION, projectName));
        process.exit(0);
      }

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
        noCache: options.cache === false,
      });

      // CI mode forces JSON output
      const outputFormat = options.ci ? 'json' : config.output;

      if (outputFormat === 'sarif') {
        if (options.sarifBaseline) {
          const baselinePath = path.resolve(options.sarifBaseline);
          try {
            const baselineJson = readFileSync(baselinePath, 'utf-8');
            const baseline = safeJsonParse<AuditReport>(baselineJson);
            console.log(renderSarifDiffReport(report, baseline, VERSION));
          } catch (err) {
            logger.error(`Failed to read SARIF baseline: ${err instanceof Error ? err.message : err}`);
            process.exit(2);
          }
        } else {
          console.log(renderSarifReport(report, VERSION));
        }
      } else if (outputFormat === 'json') {
        console.log(renderJsonReport(report));
      } else {
        console.log(renderTerminalReport(report, VERSION));
      }

      // Scan install scripts if requested
      if (options.scanScripts) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        const findings = scanInstallScripts(lockfileResult.graph, options.dir);
        if (findings.length > 0) {
          console.log('');
          console.log(chalk.bold.yellow(`⚠ ${findings.length} suspicious install scripts detected:`));
          for (const f of findings) {
            const scope = f.isProduction ? chalk.red('PROD') : chalk.dim('dev');
            console.log(`  ${scope} ${chalk.bold(f.package)}@${f.version} (${f.scriptName})`);
            for (const r of f.reasons) {
              console.log(chalk.dim(`    - ${r}`));
            }
          }
        }
      }

      // Check licenses if requested
      if (options.checkLicenses) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        const licenseFindings = scanLicenses(lockfileResult.graph, options.dir);
        if (licenseFindings.length > 0) {
          console.log('');
          console.log(chalk.bold.yellow(`⚠ ${licenseFindings.length} license concerns detected:`));
          for (const f of licenseFindings) {
            const scope = f.isProduction ? chalk.red('PROD') : chalk.dim('dev');
            const cat = f.category === 'network-copyleft' ? chalk.red(f.category) :
                        f.category === 'copyleft' ? chalk.yellow(f.category) :
                        chalk.dim(f.category);
            console.log(`  ${scope} ${chalk.bold(f.package)}@${f.version} — ${f.license} (${cat})`);
          }
        } else {
          console.log(chalk.green('\nNo license concerns detected.'));
        }
      }

      // Check dependency age if requested
      if (options.checkDepsAge) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        console.log('');
        console.log(chalk.bold('Checking dependency freshness...'));
        const ageFindings = await checkDepAge(lockfileResult.graph);
        if (ageFindings.length > 0) {
          console.log(chalk.yellow(`${ageFindings.length} packages with no updates in 2+ years:`));
          for (const f of ageFindings) {
            const scope = f.isProduction ? chalk.red('PROD') : chalk.dim('dev');
            console.log(`  ${scope} ${chalk.bold(f.package)}@${f.version} — last published ${f.lastPublished} (${f.ageMonths} months ago)`);
          }
        } else {
          console.log(chalk.green('All dependencies are actively maintained.'));
        }
      }

      // Check typosquats if requested
      if (options.checkTyposquats) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        const typosquatFindings = detectTyposquats(lockfileResult.graph);
        if (typosquatFindings.length > 0) {
          console.log('');
          console.log(chalk.bold.red(`⚠ ${typosquatFindings.length} potential typosquat packages detected:`));
          for (const f of typosquatFindings) {
            const scope = f.isProduction ? chalk.red('PROD') : chalk.dim('dev');
            console.log(`  ${scope} ${chalk.bold(f.package)}@${f.version} → similar to ${chalk.cyan(f.similarTo)}`);
            console.log(chalk.dim(`    ${f.reason}`));
          }
        } else {
          console.log(chalk.green('\nNo typosquatting concerns detected.'));
        }
      }

      // Check provenance if requested
      if (options.checkProvenance) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        console.log('');
        console.log(chalk.bold('Checking package provenance attestations...'));
        const provReport = await checkProvenance(lockfileResult.graph);
        console.log(`  Verified: ${chalk.green(String(provReport.verified))} | Unverified: ${chalk.yellow(String(provReport.unverified))}`);
        const unverifiedProd = provReport.findings.filter(f => !f.hasProvenance && f.isProduction);
        if (unverifiedProd.length > 0) {
          console.log(chalk.yellow(`  ${unverifiedProd.length} production packages lack provenance:`));
          for (const f of unverifiedProd.slice(0, 20)) {
            console.log(chalk.dim(`    ${f.package}@${f.version}`));
          }
          if (unverifiedProd.length > 20) {
            console.log(chalk.dim(`    ... and ${unverifiedProd.length - 20} more`));
          }
        }
      }

      // Scan behavior if requested
      if (options.scanBehavior) {
        const lockfileResult = detectAndParseLockfile(options.dir);
        console.log('');
        console.log(chalk.bold('Scanning package source for suspicious behavior...'));
        const behaviorFindings = scanBehavior(lockfileResult.graph, options.dir);
        if (behaviorFindings.length > 0) {
          const critCount = behaviorFindings.filter(f => f.riskLevel === 'critical').length;
          const highCount = behaviorFindings.filter(f => f.riskLevel === 'high').length;
          console.log(chalk.bold.yellow(`  ${behaviorFindings.length} packages with suspicious patterns (${critCount} critical, ${highCount} high):`));
          for (const f of behaviorFindings.slice(0, 30)) {
            const scope = f.isProduction ? chalk.red('PROD') : chalk.dim('dev');
            const risk = f.riskLevel === 'critical' ? chalk.red(f.riskLevel) :
                         f.riskLevel === 'high' ? chalk.yellow(f.riskLevel) : chalk.dim(f.riskLevel);
            console.log(`  ${scope} ${chalk.bold(f.package)}@${f.version} ${f.file} [${risk}]`);
            for (const b of f.behaviors.slice(0, 3)) {
              console.log(chalk.dim(`    L${b.line ?? '?'}: ${b.description}`));
            }
          }
        } else {
          console.log(chalk.green('No suspicious behavior patterns detected.'));
        }
      }

      // Generate VEX document if requested
      if (options.vex) {
        let projectName: string | undefined;
        try {
          const pkg = safeJsonParse<Record<string, string>>(readFileSync(join(options.dir, 'package.json'), 'utf-8'));
          projectName = pkg.name;
        } catch { /* optional */ }
        const vexDoc = generateVex(report, VERSION, projectName);
        console.log('');
        console.log(vexDoc);
      }

      // Send webhook notification if URL provided
      if (options.webhook) {
        let projectName: string | undefined;
        try {
          const pkg = safeJsonParse<Record<string, string>>(readFileSync(join(options.dir, 'package.json'), 'utf-8'));
          projectName = pkg.name;
        } catch { /* optional */ }
        const webhookResult = await sendWebhook(options.webhook, report, projectName);
        if (!webhookResult.success) {
          logger.warn(`Webhook notification failed: ${webhookResult.error}`);
        }
      }

      // Post PR comment if requested
      if (options.prComment) {
        const prResult = await postPrComment(report);
        if (prResult.success) {
          logger.info(`PR comment posted: ${prResult.commentUrl}`);
        } else {
          logger.warn(`PR comment failed: ${prResult.error}`);
        }
      }

      // Evaluate policy if present
      if (options.policy !== false) {
        try {
          const policyPath = typeof options.policy === 'string' ? options.policy : undefined;
          const policy = await loadPolicy(options.dir, policyPath);
          if (policy) {
            const findings = aggregateFindings(report);
            const policyResult = evaluatePolicy(policy, findings);
            if (!policyResult.passed) {
              console.log('');
              console.log(chalk.bold.red(`Policy violations (${policyResult.violations.length}):`));
              for (const v of policyResult.violations) {
                console.log(chalk.red(`  FAIL  ${v.finding.package}@${v.finding.version} — ${v.rule.name}`));
              }
            }
            if (policyResult.warnings.length > 0) {
              console.log('');
              console.log(chalk.bold.yellow(`Policy warnings (${policyResult.warnings.length}):`));
              for (const w of policyResult.warnings) {
                console.log(chalk.yellow(`  WARN  ${w.finding.package}@${w.finding.version} — ${w.rule.name}`));
              }
            }
            if (!policyResult.passed) {
              process.exit(1);
            }
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          logger.error(`Policy evaluation failed: ${msg}`);
          process.exit(2);
        }
      }

      // Show guided remediation plan
      if (options.remediate && report.vulnerabilities.length > 0) {
        const plan = generateRemediationPlan(report.vulnerabilities);
        console.log('');
        console.log(chalk.bold(`Remediation Plan (${plan.fixableVulns}/${plan.totalVulns} fixable):`));
        for (let i = 0; i < plan.steps.length; i++) {
          const step = plan.steps[i];
          const breaking = step.isBreaking ? chalk.red(' BREAKING') : '';
          const direct = step.isDirect ? chalk.cyan(' direct') : chalk.dim(' transitive');
          console.log(`  ${i + 1}. ${chalk.bold(step.packageName)} ${step.currentVersion} → ${chalk.green(step.fixVersion)}${direct}${breaking}`);
          console.log(chalk.dim(`     Fixes: ${step.vulnsFixed.join(', ')} (impact: ${step.impactScore})`));
        }
        if (plan.unfixable.length > 0) {
          console.log(chalk.dim(`\n  No fix available: ${plan.unfixable.join(', ')}`));
        }
      }

      // Apply fixes if requested
      if (options.fix && report.vulnerabilities.length > 0) {
        console.log('');
        const fixResult = await runFix(options.dir, report);

        // Create PR if requested and fixes were applied
        if (options.createPr && fixResult && fixResult.applied.length > 0) {
          console.log('');
          console.log(chalk.bold('Creating GitHub PR...'));
          const prResult = await createFixPr(options.dir, fixResult.applied);
          if (prResult.success) {
            console.log(chalk.green(`PR created: ${prResult.prUrl}`));
          } else {
            console.log(chalk.red(`PR creation failed: ${prResult.error}`));
          }
        }
      }

      const exitCode = options.failOn
        ? getExitCodeForStrategy(report, options.failOn)
        : getExitCode(report);
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

program
  .command('update-index')
  .description('Update the bundled offline advisory index from OSV.dev (requires network)')
  .action(async () => {
    console.log('The offline advisory index is bundled at build time.');
    console.log('To get the latest advisories, update auditfix:');
    console.log('  npm install -g auditfix@latest');
    console.log('');
    console.log('The index is a last-resort fallback. For real-time data, auditfix');
    console.log('queries OSV.dev API directly (Tier 1) on every scan.');
  });

program
  .command('diff <baseline> <current>')
  .description('Compare two auditfix JSON reports and show changes')
  .action((baselinePath: string, currentPath: string) => {
    let baselineJson: string;
    let currentJson: string;
    try {
      baselinePath = path.resolve(baselinePath);
      currentPath = path.resolve(currentPath);
      baselineJson = readFileSync(baselinePath, 'utf-8');
      currentJson = readFileSync(currentPath, 'utf-8');
    } catch (err) {
      logger.error(`Failed to read report files: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }

    const baseline = safeJsonParse<{ vulnerabilities: Array<{ id: string; package: string; installedVersion: string; severity: string; score: number }> }>(baselineJson);
    const current = safeJsonParse<{ vulnerabilities: Array<{ id: string; package: string; installedVersion: string; severity: string; score: number }> }>(currentJson);

    const diff = diffReports(baseline, current);

    if (diff.added.length > 0) {
      console.log(chalk.red.bold(`\n+ ${diff.added.length} NEW vulnerabilities:`));
      for (const v of diff.added) {
        console.log(chalk.red(`  + ${v.package}@${v.version} — ${v.id} (${v.severity}, score: ${v.score})`));
      }
    }

    if (diff.removed.length > 0) {
      console.log(chalk.green.bold(`\n- ${diff.removed.length} FIXED vulnerabilities:`));
      for (const v of diff.removed) {
        console.log(chalk.green(`  - ${v.package}@${v.version} — ${v.id} (${v.severity})`));
      }
    }

    if (diff.unchanged.length > 0) {
      console.log(chalk.dim(`\n  ${diff.unchanged.length} unchanged vulnerabilities`));
    }

    console.log('');
    if (diff.summary.improved) {
      console.log(chalk.green.bold('Result: IMPROVED — vulnerabilities reduced, none added'));
    } else if (diff.added.length > 0) {
      console.log(chalk.red.bold(`Result: REGRESSED — ${diff.added.length} new vulnerabilities`));
    } else {
      console.log(chalk.dim('Result: No change'));
    }

    // Exit 1 if there are new vulns (useful for CI gating)
    process.exit(diff.added.length > 0 ? 1 : 0);
  });

async function runFix(projectDir: string, report: import('../types/report.js').AuditReport): Promise<import('../core/fixer/lockfile-writer.js').FixResult | null> {
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
    return null;
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
    return null;
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
    return null;
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

  return result;
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
