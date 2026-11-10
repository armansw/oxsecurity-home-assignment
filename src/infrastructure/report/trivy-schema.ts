import { z } from 'zod';
import { MAX_DESCRIPTION_LENGTH, type CriticalVulnerability } from '../../domain/vulnerability.js';

/**
 * The subset of a Trivy `DetectedVulnerability` we keep. Validation runs per vulnerability object, after it
 * has been assembled from the token stream — never on the report as a whole. Unknown keys are dropped.
 */
export const TrivyVulnerabilitySchema = z.object({
  VulnerabilityID: z.string().min(1),
  PkgName: z.string().min(1),
  InstalledVersion: z.string().optional(),
  FixedVersion: z.string().optional(),
  Severity: z.literal('CRITICAL'),
  Title: z.string().optional(),
  Description: z.string().optional(),
  PrimaryURL: z.string().optional(),
  PublishedDate: z.string().optional(),
  CVSS: z.record(z.string(), z.object({ V3Score: z.number().optional() })).optional(),
});

export type TrivyVulnerability = z.infer<typeof TrivyVulnerabilitySchema>;

/** Cheap pre-filter so non-critical findings (the vast majority) never pay for schema validation. */
export function hasCriticalSeverity(value: unknown): boolean {
  return typeof value === 'object' && value !== null && 'Severity' in value && value.Severity === 'CRITICAL';
}

export function toCriticalVulnerability(v: TrivyVulnerability, target: string, pkgType: string | null): CriticalVulnerability {
  return {
    vulnerabilityId: v.VulnerabilityID,
    pkgName: v.PkgName,
    installedVersion: v.InstalledVersion ?? null,
    fixedVersion: emptyToNull(v.FixedVersion),
    severity: 'CRITICAL',
    title: v.Title ?? null,
    description: v.Description === undefined ? null : truncate(v.Description, MAX_DESCRIPTION_LENGTH),
    primaryUrl: v.PrimaryURL ?? null,
    target,
    pkgType,
    cvssScore: maxV3Score(v.CVSS),
    publishedDate: v.PublishedDate ?? null,
  };
}

function maxV3Score(cvss: TrivyVulnerability['CVSS']): number | null {
  if (cvss === undefined) return null;
  let max: number | null = null;
  for (const source of Object.values(cvss)) {
    if (source.V3Score !== undefined && (max === null || source.V3Score > max)) max = source.V3Score;
  }
  return max;
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

function emptyToNull(s: string | undefined): string | null {
  return s === undefined || s === '' ? null : s;
}
