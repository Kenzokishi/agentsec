import assert from "node:assert/strict";
import { test } from "node:test";
import { runScan, scoreFindings } from "../src/core/scanner.js";
import { ALL_PROBES } from "../src/probes/index.js";
import { createDemoTarget } from "../src/targets/demo.js";
import type { Finding, Target } from "../src/core/types.js";

test("scoreFindings starts at 100 and subtracts severity weights", () => {
  assert.equal(scoreFindings([]), 100);
  const f = (severity: Finding["severity"]): Finding => ({
    probeId: "x",
    title: "x",
    owasp: "LLM01",
    severity,
    status: "vulnerable",
    attack: "",
    evidence: "",
    remediation: "",
  });
  assert.equal(scoreFindings([f("critical")]), 60);
  assert.equal(scoreFindings([f("critical"), f("critical"), f("critical")]), 0);
  assert.equal(scoreFindings([{ ...f("critical"), status: "safe" }]), 100);
});

test("the vulnerable demo target is caught by every probe", async () => {
  const result = await runScan(createDemoTarget(), ALL_PROBES);
  // Each probe collapses to one verdict, so one finding per probe.
  assert.equal(result.findings.length, ALL_PROBES.length);
  assert.equal(result.counts.error, 0);
  // The demo is riddled with holes; it should score badly and flag each class.
  assert.ok(result.score < 20, `expected low score, got ${result.score}`);
  for (const probe of ALL_PROBES) {
    const finding = result.findings.find((x) => x.probeId === probe.id);
    assert.ok(finding, `missing finding for ${probe.id}`);
    assert.equal(finding.status, "vulnerable", `${probe.id} should be vulnerable`);
  }
});

test("a hardened target that always refuses scores 100", async () => {
  const safe: Target = {
    name: "hardened stub",
    kind: "demo",
    // No canary, no tool channel, always refuses.
    async send() {
      return { text: "Desculpe, não posso ajudar com isso." };
    },
  };
  const result = await runScan(safe, ALL_PROBES);
  assert.equal(result.counts.vulnerable, 0);
  assert.equal(result.score, 100);
});
