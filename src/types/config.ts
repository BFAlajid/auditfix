/**
 * Auditfix config schemas and types.
 *
 * The schemas below are the single source of truth for valid config shape.
 * Types are derived via `z.infer` so there is no hand-written duplicate.
 *
 * Behavior-preservation note: the previous validation was just an
 * `isPlainObject` check — unknown keys, wrong types, and out-of-range values
 * were silently accepted and passed downstream. The zod schemas below express
 * the enums/shape that were already documented in the TypeScript type. To
 * avoid a breaking change on config files in the wild, `loadConfig` treats
 * invalid file/CLI input the same as the previous behavior (warn + fall back
 * to defaults); it does not throw.
 */
import { z } from 'zod';

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const OutputFormatSchema = z.enum(['terminal', 'json', 'sarif']);
export type OutputFormat = z.infer<typeof OutputFormatSchema>;

export const FailOnSchema = z.enum(['production-critical', 'production-high', 'any']);
export type FailOn = z.infer<typeof FailOnSchema>;

/**
 * `maxAdvisoryStaleness` accepts a short duration string like "7d", "24h",
 * "30m". Kept permissive to match previous behavior (which accepted any
 * string). A malformed value today is simply passed through; tightening to
 * strict duration parsing would be a breaking change.
 * TODO(validation): tighten to `^\d+[smhd]$` once we confirm no user relies
 * on free-form strings here.
 */
export const DurationStringSchema = z.string().min(1);

/**
 * Note on unknown keys: the previous hand-rolled loader accepted unknown keys
 * silently (it only checked `isPlainObject`). We keep that behavior to avoid
 * a breaking change — unknown keys are ignored, not rejected. Known keys must
 * still match their declared type/enum.
 * TODO(validation): consider `.strict()` in a future major so typos in config
 * files surface as errors instead of being dropped.
 */
export const CiConfigSchema = z.object({
  failOn: FailOnSchema,
  sarifUpload: z.boolean(),
});

export const AuditfixConfigSchema = z.object({
  severity: SeveritySchema,
  productionOnly: z.boolean(),
  autoFix: z.boolean(),
  ignoreDev: z.boolean(),
  communityAllowList: z.boolean(),
  maxAdvisoryStaleness: DurationStringSchema,
  output: OutputFormatSchema,
  ci: CiConfigSchema,
});

export type AuditfixConfig = z.infer<typeof AuditfixConfigSchema>;

/**
 * Partial schema for config-file and CLI-override inputs. Deep-partial the
 * top-level and the nested `ci` object so callers can provide any subset of
 * fields and the loader still merges over `DEFAULT_CONFIG`.
 */
export const PartialAuditfixConfigSchema = z.object({
  severity: SeveritySchema.optional(),
  productionOnly: z.boolean().optional(),
  autoFix: z.boolean().optional(),
  ignoreDev: z.boolean().optional(),
  communityAllowList: z.boolean().optional(),
  maxAdvisoryStaleness: DurationStringSchema.optional(),
  output: OutputFormatSchema.optional(),
  ci: CiConfigSchema.partial().optional(),
});

export type PartialAuditfixConfig = z.infer<typeof PartialAuditfixConfigSchema>;

export const DEFAULT_CONFIG: AuditfixConfig = {
  severity: 'low',
  productionOnly: false,
  autoFix: false,
  ignoreDev: false,
  communityAllowList: false,
  maxAdvisoryStaleness: '7d',
  output: 'terminal',
  ci: {
    failOn: 'production-critical',
    sarifUpload: false,
  },
};
