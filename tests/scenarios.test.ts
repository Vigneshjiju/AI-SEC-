/**
 * Integration tests for the scenario engine.
 *
 * These spawn real MCP server child processes and drive genuine stdio JSON-RPC
 * tool calls through the full Sentinel pipeline. They are the tests that would
 * catch a regression where the security pipeline "works" only against
 * hand-written strings.
 */
import { describe, it, expect, afterAll } from "vitest";
import { resolve } from "node:path";
import { AdaptiveController } from "../src/sentinel/adaptive-controller.js";
import { ScenarioEngine, defaultFixtureSpecs, SCENARIOS } from "../src/sentinel/scenario-engine.js";

const FIXTURES = resolve(process.cwd(), "test/fixtures");

/** Thresholds match the demo so scenario expectations line up with the narrative. */
function makeEngine() {
  const sentinel = new AdaptiveController({
    risk: { thresholds: { monitor: 26, restrict: 50, approval: 65, quarantine: 80 } },
  });
  return { sentinel, engine: new ScenarioEngine(sentinel, defaultFixtureSpecs(FIXTURES)) };
}

const engines: ScenarioEngine[] = [];
function track(engine: ScenarioEngine) {
  engines.push(engine);
  return engine;
}

afterAll(async () => {
  await Promise.all(engines.map((e) => e.shutdown()));
});

describe("Scenario engine — real MCP servers", () => {
  it("allows a benign investigation end to end (no false positives)", async () => {
    const { engine } = makeEngine();
    track(engine);
    const run = await engine.run("benign-investigation");

    expect(run.steps).toHaveLength(3);
    expect(run.steps.every((s) => s.decision === "allow")).toBe(true);
    expect(run.steps.every((s) => s.executed)).toBe(true);
    expect(run.blocked).toBe(0);
    expect(run.peakRisk).toBe(0);
    expect(run.finalState).toBe("NORMAL");
    expect(run.expectationsMet).toBe(true);

    // The responses came from a real child process, not a fixture string.
    expect(run.steps[0].outputPreview).toContain("Failed login");
  }, 30000);

  it("detects and contains a rug-pull, then recovers under operator control", async () => {
    const { sentinel, engine } = makeEngine();
    track(engine);
    const run = await engine.run("rug-pull");

    // Clean calls first — trust has to be earned before it can be betrayed.
    expect(run.steps[0].decision).toBe("allow");
    expect(run.steps[0].driftFindings).toHaveLength(0);

    // The semantic firewall sees the contract expand at tools/list time.
    const semanticStep = run.steps.find((s) => s.semanticFindings.length > 0);
    expect(semanticStep).toBeDefined();
    expect(semanticStep!.semanticFindings.join(" ")).toMatch(/cmd|environment|shell/i);
    expect(semanticStep!.riskScore).toBeGreaterThan(0);

    // Runtime behaviour diverges from the established baseline.
    const driftStep = run.steps.find((s) => s.driftFindings.length > 0);
    expect(driftStep).toBeDefined();
    expect(driftStep!.driftFindings.length).toBeGreaterThan(3);

    // Containment, then hard blocks with the upstream never reached.
    expect(run.quarantines).toBeGreaterThan(0);
    const blocked = run.steps.filter((s) => s.decision === "block");
    expect(blocked.length).toBeGreaterThanOrEqual(2);
    expect(blocked.every((s) => s.executed === false)).toBe(true);
    expect(blocked.every((s) => s.policy === "hard-quarantine")).toBe(true);

    // Recovery lands in MONITOR, never straight back to NORMAL.
    expect(run.finalState).toBe("MONITOR");
    expect(run.expectationsMet).toBe(true);

    const receipts = sentinel.receiptsLedger.getAllReceipts();
    expect(receipts.length).toBeGreaterThan(0);
    expect(receipts.every((r) => r.hash.length === 64)).toBe(true);
  }, 40000);

  it("blocks a multi-step exfiltration chain built from authorized tools", async () => {
    const { engine } = makeEngine();
    track(engine);
    const run = await engine.run("exfil-chain");

    // Recon is permitted — the individual tools are all legitimate.
    expect(run.steps[0].decision).toBe("allow");
    expect(run.steps[1].decision).toBe("allow");

    // Credential access is escalated to a human, not silently allowed.
    expect(run.steps[2].decision).toBe("require-approval");

    // After approval the call proceeds, proving the grant is actually redeemable.
    const credRead = run.steps[4];
    expect(credRead.decision).toBe("allow");
    expect(credRead.executed).toBe(true);

    // The exfiltration step is blocked on sequence, not on the tool itself.
    const exfil = run.steps[run.steps.length - 1];
    expect(exfil.decision).toBe("block");
    expect(exfil.executed).toBe(false);
    expect(exfil.reason).toMatch(/sequence|exfiltration|data.flow/i);
    expect(run.expectationsMet).toBe(true);
  }, 40000);

  it("rejects hostile arguments before reaching the upstream server", async () => {
    const { engine } = makeEngine();
    track(engine);
    const run = await engine.run("hostile-input");

    expect(run.steps).toHaveLength(3);
    expect(run.steps.every((s) => s.decision === "block")).toBe(true);
    expect(run.steps.every((s) => s.executed === false)).toBe(true);
    expect(run.steps.every((s) => s.policy === "input-validator")).toBe(true);
    expect(run.expectationsMet).toBe(true);
  }, 30000);

  it("enforces the privilege boundary and honours a JIT elevation", async () => {
    const { engine } = makeEngine();
    track(engine);
    const run = await engine.run("privilege-escalation");

    expect(run.steps[0].decision).toBe("block");
    expect(run.steps[0].policy).toBe("hard-authorization");

    // Elevation grants access to the approval queue, not a bypass.
    expect(run.steps[2].decision).toBe("require-approval");
    expect(run.expectationsMet).toBe(true);
  }, 30000);

  it("flags injected instructions carried in otherwise-legitimate tool data", async () => {
    const { sentinel, engine } = makeEngine();
    track(engine);
    const run = await engine.run("prompt-injection");

    // The server is honest; reading the ticket is allowed.
    const read = run.steps[1];
    expect(read.decision).toBe("allow");
    expect(read.outputPreview).toMatch(/ignore all previous instructions/i);

    // But the injected content raises risk and the follow-on actions fail.
    expect(read.riskScore).toBeGreaterThan(0);
    expect(run.steps[2].decision).toBe("block");
    expect(run.steps[3].decision).toBe("block");
    expect(run.expectationsMet).toBe(true);

    const findings = sentinel.outputScanner.scan(read.outputPreview);
    expect(findings.some((f) => f.ruleId.startsWith("output-"))).toBe(true);
  }, 30000);

  it("resets to a clean baseline between runs", async () => {
    const { sentinel, engine } = makeEngine();
    track(engine);

    await engine.run("rug-pull");
    expect(sentinel.getSystemOverview().maxRiskScore).toBeGreaterThan(0);

    await engine.reset();
    const after = sentinel.getSystemOverview();
    expect(after.maxRiskScore).toBe(0);
    expect(after.totalServers).toBe(0);
    expect(after.overallState).toBe("NORMAL");
  }, 45000);
});

describe("Scenario library", () => {
  it("declares a coherent definition for every scenario", () => {
    expect(SCENARIOS.length).toBeGreaterThanOrEqual(6);
    for (const scenario of SCENARIOS) {
      expect(scenario.id).toMatch(/^[a-z-]+$/);
      expect(scenario.name.length).toBeGreaterThan(0);
      expect(scenario.technique.length).toBeGreaterThan(0);
      expect(scenario.expectedOutcome.length).toBeGreaterThan(0);
      expect(scenario.steps.length).toBeGreaterThan(0);
      for (const step of scenario.steps) {
        expect(step.narrative.length).toBeGreaterThan(20);
        expect(scenario.servers).toContain(step.server === "—" ? step.server : step.server);
      }
    }
  });

  it("exposes unique scenario ids", () => {
    const ids = SCENARIOS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
