import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "../core/types.js";

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(s)),
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
  info: pc.dim,
};

function scoreColor(score: number): (s: string) => string {
  if (score >= 80) return pc.green;
  if (score >= 50) return pc.yellow;
  return pc.red;
}

function statusBadge(f: Finding): string {
  if (f.status === "vulnerable") return SEV_COLOR[f.severity](` VULN `);
  if (f.status === "error") return pc.bgYellow(pc.black(" ERR  "));
  return pc.green(" PASS ");
}

export function renderConsole(result: ScanResult): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(pc.bold(`  agentsec · ${result.target}`));
  lines.push(pc.dim(`  ${result.findings.length} probes · ${result.startedAt}`));
  lines.push("");

  for (const f of result.findings) {
    lines.push(`  ${statusBadge(f)} ${pc.bold(f.title)} ${pc.dim(`[${f.owasp}]`)}`);
    lines.push(`         ${pc.dim(f.evidence)}`);
    if (f.status === "vulnerable") {
      lines.push(`         ${pc.dim("fix:")} ${pc.dim(f.remediation)}`);
    }
    lines.push("");
  }

  const score = scoreColor(result.score);
  lines.push(
    `  ${pc.bold("Score:")} ${score(pc.bold(String(result.score)))}/100` +
      pc.dim(
        `   ${result.counts.vulnerable} vulnerable · ${result.counts.safe} safe · ${result.counts.error} errors`,
      ),
  );
  lines.push("");
  return lines.join("\n");
}
