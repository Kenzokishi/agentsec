/**
 * Core contracts for the scanner.
 *
 * The design has three moving parts:
 *   - Target: anything you can send a message to (a chat endpoint, an MCP
 *     server, or the built-in vulnerable demo). It answers with text and,
 *     optionally, the tool calls it decided to make.
 *   - Probe: one attack technique. It sends crafted inputs to a Target and
 *     inspects the responses for evidence that the attack worked.
 *   - Finding: the verdict a Probe reaches, mapped to an OWASP LLM Top 10 id.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** OWASP Top 10 for LLM Applications (2025) identifiers. */
export type OwaspLlmId =
  | "LLM01" // Prompt Injection
  | "LLM02" // Sensitive Information Disclosure
  | "LLM06" // Excessive Agency
  | "LLM07" // System Prompt Leakage
  | "LLM08"; // Vector & Embedding Weaknesses (reserved for later probes)

export interface ToolCall {
  /** Name of the tool/function the target decided to invoke. */
  name: string;
  /** Raw arguments the target passed, as a JSON-serialisable object. */
  args: Record<string, unknown>;
}

export interface TargetResponse {
  /** The natural-language reply the target produced. */
  text: string;
  /** Tool calls the target emitted, when it exposes an agent/tool loop. */
  toolCalls?: ToolCall[];
}

export interface Target {
  /** Human-readable label shown in the report. */
  name: string;
  /** What kind of thing is behind this target. */
  kind: "demo" | "http" | "mcp";
  /**
   * A tagged secret planted in the target's context. Leak and exfiltration
   * probes check whether they can make the target reveal this exact string.
   * Only the demo target knows its own secret; for real targets this is left
   * undefined and those probes fall back to heuristic detection.
   */
  canarySecret?: string;
  /** Send one user turn and get the target's response. */
  send(input: string): Promise<TargetResponse>;
}

export interface Finding {
  probeId: string;
  title: string;
  owasp: OwaspLlmId;
  severity: Severity;
  status: "vulnerable" | "safe" | "error";
  /** What we sent, trimmed, so the report can show the attack. */
  attack: string;
  /** Why we reached this verdict (the giveaway in the response, or the error). */
  evidence: string;
  /** Concrete fix suggestion shown when status is "vulnerable". */
  remediation: string;
}

export interface ProbeContext {
  /** Emits a line of progress while a probe runs. */
  log(message: string): void;
}

export interface Probe {
  id: string;
  name: string;
  owasp: OwaspLlmId;
  /** Severity this probe reports when it finds the target is vulnerable. */
  severity: Severity;
  /** One-line description shown in `agentsec list`. */
  description: string;
  run(target: Target, ctx: ProbeContext): Promise<Finding[]>;
}

export interface ScanResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  findings: Finding[];
  /** 0-100, where 100 means every probe reported the target safe. */
  score: number;
  counts: Record<Finding["status"], number>;
}
