import type { Finding, Probe, ScanResult, Severity, Target } from "./types.js";

/** Weight each severity carries when it is found to be vulnerable. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
  info: 0,
};

/**
 * Turn a list of findings into a 0-100 score. We start at 100 and subtract the
 * weight of every vulnerable finding, clamped at 0. Errors don't move the score
 * (we couldn't test), but they are surfaced in the counts so they aren't hidden.
 */
export function scoreFindings(findings: Finding[]): number {
  let penalty = 0;
  for (const f of findings) {
    if (f.status === "vulnerable") penalty += SEVERITY_WEIGHT[f.severity];
  }
  return Math.max(0, 100 - penalty);
}

export interface RunOptions {
  /** Called with a status line as each probe starts and finishes. */
  onProgress?: (message: string) => void;
}

export async function runScan(
  target: Target,
  probes: Probe[],
  options: RunOptions = {},
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];
  const log = (m: string) => options.onProgress?.(m);

  for (const probe of probes) {
    log(`▶ ${probe.id} — ${probe.name}`);
    try {
      const probeFindings = await probe.run(target, { log });
      findings.push(...probeFindings);
    } catch (err) {
      findings.push({
        probeId: probe.id,
        title: `${probe.name} (probe crashed)`,
        owasp: probe.owasp,
        severity: "info",
        status: "error",
        attack: "—",
        evidence: err instanceof Error ? err.message : String(err),
        remediation:
          "This is a scanner-side error, not a target vulnerability. Re-run with --verbose to inspect.",
      });
    }
  }

  const counts: ScanResult["counts"] = { vulnerable: 0, safe: 0, error: 0 };
  for (const f of findings) counts[f.status] += 1;

  return {
    target: target.name,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings,
    score: scoreFindings(findings),
    counts,
  };
}
