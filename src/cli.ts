import { writeFile } from "node:fs/promises";
import pc from "picocolors";
import { runScan } from "./core/scanner.js";
import { ALL_PROBES, selectProbes } from "./probes/index.js";
import { renderConsole } from "./report/console.js";
import { renderMarkdown } from "./report/markdown.js";
import { createDemoTarget } from "./targets/demo.js";
import { createHttpTarget } from "./targets/http.js";
import type { Target } from "./core/types.js";

interface Flags {
  _: string[];
  [key: string]: string | boolean | string[];
}

/** Minimal flag parser: `--key value`, `--key=value`, and boolean `--flag`. */
function parseArgs(argv: string[]): Flags {
  const flags: Flags = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, inlineV] = a.slice(2).split("=", 2);
      if (inlineV !== undefined) {
        flags[k] = inlineV;
      } else if (argv[i + 1] && !argv[i + 1].startsWith("--")) {
        flags[k] = argv[++i];
      } else {
        flags[k] = true;
      }
    } else {
      (flags._ as string[]).push(a);
    }
  }
  return flags;
}

const HELP = `
${pc.bold("agentsec")} — red-team scanner for LLM apps, agents and MCP servers

${pc.bold("Usage")}
  agentsec scan --target <demo|url> [options]
  agentsec list
  agentsec --help

${pc.bold("Options")}
  --target <t>      "demo" (built-in vulnerable agent, no key needed) or an
                    OpenAI-compatible chat completions URL.
  --model <m>       Model name for an http target (default: gpt-4o-mini).
  --probes <a,b>    Comma-separated probe ids to run (default: all).
  --report <fmt>    "console" (default) or "md".
  --out <file>      Write the report to a file instead of stdout.
  --fail-under <n>  Exit 1 if the score is below n (for CI gates).
  --verbose         Print per-payload progress while probing.

${pc.bold("Examples")}
  npx agentsec scan --target demo
  npx agentsec scan --target https://api.openai.com/v1/chat/completions --model gpt-4o-mini
  npx agentsec scan --target demo --report md --out report.md
  npx agentsec scan --target demo --fail-under 80
`;

function resolveTarget(flags: Flags): Target {
  const t = String(flags.target ?? "demo");
  if (t === "demo") return createDemoTarget();
  if (t.startsWith("http://") || t.startsWith("https://")) {
    return createHttpTarget({ url: t, model: flags.model ? String(flags.model) : undefined });
  }
  throw new Error(`unknown target "${t}". Use "demo" or a full http(s) URL.`);
}

export async function main(argv: string[]): Promise<number> {
  const flags = parseArgs(argv);
  const command = (flags._ as string[])[0] ?? (flags.help ? "help" : "help");

  if (command === "help" || flags.help) {
    process.stdout.write(HELP + "\n");
    return 0;
  }

  if (command === "list") {
    process.stdout.write("\n" + pc.bold("  Available probes\n\n"));
    for (const p of ALL_PROBES) {
      process.stdout.write(
        `  ${pc.cyan(p.id.padEnd(22))} ${pc.dim(`[${p.owasp}]`)} ${p.description}\n`,
      );
    }
    process.stdout.write("\n");
    return 0;
  }

  if (command !== "scan") {
    process.stderr.write(pc.red(`unknown command "${command}"\n`) + HELP + "\n");
    return 2;
  }

  const target = resolveTarget(flags);
  const probeIds = flags.probes ? String(flags.probes).split(",").map((s) => s.trim()) : undefined;
  const probes = selectProbes(probeIds);
  const verbose = Boolean(flags.verbose);

  process.stderr.write(pc.dim(`\nScanning ${target.name} with ${probes.length} probe(s)…\n`));

  const result = await runScan(target, probes, {
    onProgress: (m) => {
      if (verbose) process.stderr.write(pc.dim(`  ${m}\n`));
    },
  });

  const format = String(flags.report ?? "console");
  const rendered = format === "md" ? renderMarkdown(result) : renderConsole(result);

  if (flags.out) {
    await writeFile(String(flags.out), rendered, "utf8");
    process.stderr.write(pc.green(`\nReport written to ${flags.out}\n`));
  } else {
    process.stdout.write(rendered + "\n");
  }

  if (flags["fail-under"] !== undefined) {
    const threshold = Number(flags["fail-under"]);
    if (result.score < threshold) {
      process.stderr.write(
        pc.red(`\nScore ${result.score} is below --fail-under ${threshold}\n`),
      );
      return 1;
    }
  }
  return 0;
}
