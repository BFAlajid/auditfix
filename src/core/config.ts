/**
 * Config file loading via lilconfig.
 * Searches for .auditfixrc.json, .auditfixrc.yml, auditfix.config.js, etc.
 * Merges: defaults -> config file -> CLI overrides.
 */
import { lilconfig } from 'lilconfig';
import type { AuditfixConfig } from '../types/config.js';
import { DEFAULT_CONFIG } from '../types/config.js';
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
  let fileConfig: Partial<AuditfixConfig> = {};

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
        fileConfig = result.config as Partial<AuditfixConfig>;
        logger.debug(`Loaded config from ${result.filepath}`);
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

  // Deep merge for the nested `ci` config
  const mergedCi = {
    ...DEFAULT_CONFIG.ci,
    ...(isPlainObject(fileConfig.ci) ? fileConfig.ci : {}),
    ...(isPlainObject(cleanOverrides.ci) ? cleanOverrides.ci : {}),
  };

  // Shallow merge for top-level, then assign deep-merged ci
  const merged: AuditfixConfig = {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    ...cleanOverrides,
    ci: mergedCi,
  };

  return merged;
}
