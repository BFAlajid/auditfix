/**
 * Config file loading via lilconfig.
 * Searches for .auditfixrc.json, .auditfixrc.yml, auditfix.config.js, etc.
 * Merges: defaults -> config file -> CLI overrides.
 *
 * Validation is done with zod schemas from `../types/config.js`. Invalid
 * file content or CLI overrides trigger a warning and fall back to the
 * existing defaults; behavior matches the previous hand-rolled loader so
 * no user configs in the wild break on upgrade.
 */
import { lilconfig } from 'lilconfig';
import type { ZodError, ZodIssue } from 'zod';
import {
  DEFAULT_CONFIG,
  PartialAuditfixConfigSchema,
  type AuditfixConfig,
  type PartialAuditfixConfig,
} from '../types/config.js';
import { safeYamlParse } from '../utils/sanitize.js';
import * as logger from '../utils/logger.js';

/**
 * Remove keys with undefined values from an object (shallow).
 * This ensures only explicitly-set CLI overrides are merged.
 */
function stripUndefined<T extends Record<string, unknown>>(obj: T): Partial<T> {
  const result: Partial<T> = {};
  for (const key of Object.keys(obj) as Array<keyof T>) {
    if (obj[key] !== undefined) {
      result[key] = obj[key];
    }
  }
  return result;
}

/**
 * Validate that a loaded config value is a plain object.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Render a zod error into a compact, human-readable string. Used in log
 * messages so operators can see which field was wrong and why without
 * needing to parse a raw zod dump.
 */
function formatZodError(error: ZodError): string {
  return error.issues
    .map((issue: ZodIssue) => {
      const path = issue.path.length === 0 ? '<root>' : issue.path.join('.');
      return `${path}: ${issue.message}`;
    })
    .join('; ');
}

/**
 * Validate a partial config object (file contents or CLI overrides) against
 * the schema. On failure, emit a warning that names the source and returns
 * `null` so the caller can fall back to defaults / the previous layer.
 */
function validatePartial(
  value: unknown,
  source: string,
): PartialAuditfixConfig | null {
  const parsed = PartialAuditfixConfigSchema.safeParse(value);
  if (!parsed.success) {
    logger.warn(
      `Invalid ${source}: ${formatZodError(parsed.error)} — falling back to defaults`,
    );
    return null;
  }
  return parsed.data;
}

/**
 * Load config from .auditfixrc.json, .auditfixrc.yaml, etc.
 * Returns merged config: defaults -> config file -> CLI overrides.
 *
 * @param cliOverrides - Values from CLI flags. Only non-undefined keys are merged.
 * @param projectDir - Directory to search for config files.
 */
export async function loadConfig(
  cliOverrides: Partial<AuditfixConfig>,
  projectDir: string,
): Promise<AuditfixConfig> {
  let fileConfig: PartialAuditfixConfig = {};

  try {
    const yamlLoader = (_filepath: string, content: string) => safeYamlParse(content);
    const searcher = lilconfig('auditfix', {
      searchPlaces: [
        '.auditfixrc',
        '.auditfixrc.json',
        '.auditfixrc.yml',
        '.auditfixrc.yaml',
        'package.json',
      ],
      loaders: {
        '.yml': yamlLoader,
        '.yaml': yamlLoader,
      },
    });
    const result = await searcher.search(projectDir);

    if (result && !result.isEmpty) {
      if (isPlainObject(result.config)) {
        const validated = validatePartial(
          result.config,
          `config file ${result.filepath}`,
        );
        if (validated !== null) {
          fileConfig = validated;
          logger.debug(`Loaded config from ${result.filepath}`);
        }
      } else {
        logger.warn(
          `Config file ${result.filepath} does not export a plain object — using defaults`,
        );
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(`Failed to load config file: ${message} — using defaults`);
  }

  // Strip undefined keys from CLI overrides so they don't clobber file/default values
  const cleanOverrides = stripUndefined(cliOverrides);

  // Validate CLI overrides. If invalid, drop them (warn issued inside).
  let validatedOverrides: PartialAuditfixConfig = {};
  if (Object.keys(cleanOverrides).length > 0) {
    const parsedOverrides = validatePartial(cleanOverrides, 'CLI overrides');
    if (parsedOverrides !== null) {
      validatedOverrides = parsedOverrides;
    }
  }

  // Deep merge for the nested `ci` config
  const mergedCi = {
    ...DEFAULT_CONFIG.ci,
    ...(isPlainObject(fileConfig.ci) ? fileConfig.ci : {}),
    ...(isPlainObject(validatedOverrides.ci) ? validatedOverrides.ci : {}),
  };

  // Shallow merge for top-level, then assign deep-merged ci
  const merged: AuditfixConfig = {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    ...validatedOverrides,
    ci: mergedCi,
  };

  return merged;
}
