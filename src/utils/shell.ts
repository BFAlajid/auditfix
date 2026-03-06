/**
 * Safe child_process wrapper.
 * NEVER uses exec() with string interpolation — only execFile/spawn with argument arrays.
 * This bypasses the shell entirely, preventing injection.
 */
import { execFile as execFileCb, type ExecFileOptions } from 'node:child_process';
import { promisify } from 'node:util';
import { isValidPackageName } from './sanitize.js';
import * as logger from './logger.js';

const execFileAsync = promisify(execFileCb);

const MAX_VERSION_LENGTH = 256;
const VERSION_RE = /^[a-zA-Z0-9._\-+>=<^~| ]+$/;

export type ShellResult = {
  stdout: string;
  stderr: string;
  exitCode: number;
};

/**
 * Execute a command safely using execFile (no shell interpolation).
 * All arguments are passed as an array — never concatenated into a string.
 */
export async function safeExec(
  command: string,
  args: string[],
  options?: ExecFileOptions,
): Promise<ShellResult> {
  logger.debug(`exec: ${command} ${args.join(' ')}`);

  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: 60_000,
      maxBuffer: 10 * 1024 * 1024, // 10MB
      ...options,
    });

    return {
      stdout: stdout?.toString() ?? '',
      stderr: stderr?.toString() ?? '',
      exitCode: 0,
    };
  } catch (err: unknown) {
    const error = err as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: error.stdout?.toString() ?? '',
      stderr: error.stderr?.toString() ?? '',
      exitCode: error.code ?? 1,
    };
  }
}

/**
 * Validate a version string before passing to any shell command.
 */
export function isValidShellVersion(version: string): boolean {
  if (version.length > MAX_VERSION_LENGTH) return false;
  return VERSION_RE.test(version);
}

/**
 * Validate all inputs before constructing an npm override command.
 * Throws if any input is suspicious.
 */
export function validateFixInputs(
  packageName: string,
  version: string,
): void {
  if (!isValidPackageName(packageName)) {
    throw new Error(`Invalid package name for fix: ${packageName}`);
  }
  if (!isValidShellVersion(version)) {
    throw new Error(`Invalid version string for fix: ${version}`);
  }
}
