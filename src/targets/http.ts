import type { Target, TargetResponse } from "../core/types.js";

export interface HttpTargetConfig {
  /** Full URL of an OpenAI-compatible chat completions endpoint. */
  url: string;
  /** Model name to send in the request body. */
  model?: string;
  /** Bearer token; read from AGENTSEC_API_KEY if omitted. */
  apiKey?: string;
  /** Extra headers to merge into the request. */
  headers?: Record<string, string>;
}

/**
 * Targets any OpenAI-compatible `/chat/completions` endpoint — OpenAI, Azure,
 * Groq, Ollama, vLLM, LM Studio, or your own gateway. The scanner only needs
 * one user turn in and the assistant's text out, so this stays deliberately
 * thin. Tool-call inspection for arbitrary HTTP agents is left for a later
 * version; the demo and MCP targets already exercise the tool-abuse probes.
 */
export function createHttpTarget(config: HttpTargetConfig): Target {
  const apiKey = config.apiKey ?? process.env.AGENTSEC_API_KEY;
  const model = config.model ?? "gpt-4o-mini";

  return {
    name: `http (${new URL(config.url).host} · ${model})`,
    kind: "http",
    async send(input: string): Promise<TargetResponse> {
      const res = await fetch(config.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
          ...config.headers,
        },
        body: JSON.stringify({
          model,
          messages: [{ role: "user", content: input }],
          temperature: 0,
        }),
      });

      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(
          `target returned HTTP ${res.status} ${res.statusText}: ${body.slice(0, 300)}`,
        );
      }

      const data = (await res.json()) as {
        choices?: { message?: { content?: string } }[];
      };
      const text = data.choices?.[0]?.message?.content ?? "";
      return { text };
    },
  };
}
