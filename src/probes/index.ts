import type { Probe } from "../core/types.js";
import { excessiveAgencyProbe } from "./excessive-agency.js";
import { promptInjectionProbe } from "./prompt-injection.js";
import { sensitiveDisclosureProbe } from "./sensitive-disclosure.js";
import { systemPromptLeakProbe } from "./system-prompt-leak.js";

/** All probes the scanner ships with, in report order. */
export const ALL_PROBES: Probe[] = [
  promptInjectionProbe,
  systemPromptLeakProbe,
  sensitiveDisclosureProbe,
  excessiveAgencyProbe,
];

export function selectProbes(ids?: string[]): Probe[] {
  if (!ids || ids.length === 0) return ALL_PROBES;
  const wanted = new Set(ids);
  return ALL_PROBES.filter((p) => wanted.has(p.id));
}
