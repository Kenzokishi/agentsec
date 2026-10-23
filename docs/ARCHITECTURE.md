# Architecture

`agentsec` is intentionally small. The whole thing is three contracts in
`src/core/types.ts` and a handful of files that implement them.

```
          ┌─────────────┐     sends crafted inputs      ┌──────────────┐
          │   Probe     │ ────────────────────────────▶ │   Target     │
          │ (an attack) │ ◀──────────────────────────── │ (the system) │
          └─────────────┘     reply + tool calls         └──────────────┘
                 │
                 │ produces Finding[]
                 ▼
          ┌─────────────┐     scores + renders          ┌──────────────┐
          │  Scanner    │ ────────────────────────────▶ │   Report     │
          └─────────────┘                                └──────────────┘
```

## The three contracts

### Target
Anything you can send one message to and get a reply from. A target may also
expose the **tool calls** the model decided to make — that is what lets the
excessive-agency probe prove a real action, not just bad text.

```ts
interface Target {
  name: string;
  kind: "demo" | "http" | "mcp";
  canarySecret?: string;          // planted secret, for leak/exfil probes
  send(input: string): Promise<{ text: string; toolCalls?: ToolCall[] }>;
}
```

Implementations: `targets/demo.ts` (the bundled vulnerable agent) and
`targets/http.ts` (any OpenAI-compatible endpoint).

### Probe
One attack technique. It sends payloads, inspects the responses, and returns a
`Finding` with a verdict (`vulnerable` / `safe` / `error`), the exact attack
sent, the evidence, and a concrete fix.

```ts
interface Probe {
  id: string;
  owasp: OwaspLlmId;              // maps the finding to the OWASP LLM Top 10
  severity: Severity;
  run(target: Target, ctx: ProbeContext): Promise<Finding[]>;
}
```

### Scanner
Runs the selected probes against a target, catches probe crashes as `error`
findings (so one bad probe never aborts the scan), and computes the score:
start at 100, subtract each vulnerable finding's severity weight, clamp at 0.

## Adding a probe

1. Create `src/probes/my-probe.ts` exporting a `Probe`.
2. Register it in `src/probes/index.ts`.
3. The report, scoring, and CLI pick it up automatically.

Detection should be **generic**, not tuned to the demo: rely on signals like a
leaked canary, absent refusal, or an attacker-controlled tool call — things
that mean the same thing for any target.

## Why detection is heuristic

For a real target we don't know the ground truth, so probes use conservative
signals (e.g. require the planted canary, or 2+ system-prompt markers) to keep
false positives low. The demo target has a known secret, which is what makes the
test suite able to assert exact verdicts.
