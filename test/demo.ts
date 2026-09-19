/**
 * MCP-Sentinel: End-to-End Terminal Demonstration
 *
 * Runs the real scenario engine. Every tool response printed below was produced
 * by an actual MCP server child process over stdio, and every verdict, risk
 * score and state transition was computed by the control plane from those
 * bytes. Nothing in this script fabricates output or asserts an outcome.
 *
 * Usage:
 *   npm run demo                  # the signature rug-pull scenario
 *   npm run demo -- --all         # every scenario
 *   npm run demo -- exfil-chain   # one specific scenario
 *   npm run demo -- --dashboard   # also serve the live console on :3100
 */

import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AdaptiveController } from "../src/sentinel/adaptive-controller.js";
import { ScenarioEngine, defaultFixtureSpecs } from "../src/sentinel/scenario-engine.js";
import type { ScenarioRunResult, ScenarioStepResult } from "../src/sentinel/scenario-engine.js";
import { startDashboard } from "../src/dashboard/server.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const c = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  cyan: "\x1b[36m", green: "\x1b[32m", yellow: "\x1b[33m",
  red: "\x1b[31m", magenta: "\x1b[35m", blue: "\x1b[34m", grey: "\x1b[90m",
  bgRed: "\x1b[41m\x1b[97m", bgGreen: "\x1b[42m\x1b[30m",
  bgYellow: "\x1b[43m\x1b[30m", bgBlue: "\x1b[44m\x1b[97m",
};

const W = 84;

function rule(char = "─") { return char.repeat(W); }

function banner(title: string, subtitle?: string) {
  console.log(`\n${c.cyan}${rule("═")}${c.reset}`);
  console.log(`${c.bold}${c.cyan}  ${title}${c.reset}`);
  if (subtitle) console.log(`${c.dim}  ${subtitle}${c.reset}`);
  console.log(`${c.cyan}${rule("═")}${c.reset}`);
}

function verdictBadge(decision: string): string {
  switch (decision) {
    case "allow": return `${c.bgGreen} ALLOW ${c.reset}`;
    case "block": return `${c.bgRed} BLOCK ${c.reset}`;
    case "require-approval": return `${c.bgYellow} APPROVAL ${c.reset}`;
    default: return `${c.bgBlue} OPERATOR ${c.reset}`;
  }
}

function stateColor(state: string): string {
  switch (state) {
    case "QUARANTINE": return c.red;
    case "HUMAN_APPROVAL": return c.magenta;
    case "RESTRICT": return c.yellow;
    case "MONITOR": return c.cyan;
    default: return c.green;
  }
}

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if ((line + " " + word).trim().length > width) {
      lines.push(line.trim());
      line = word;
    } else {
      line += " " + word;
    }
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => indent + l).join("\n");
}

function printStep(step: ScenarioStepResult) {
  const n = `${step.index + 1}/${step.total}`;
  console.log(`\n${c.bold}  [${n}] ${step.title}${c.reset}  ${c.grey}(${step.phase})${c.reset}`);
  console.log(wrap(step.narrative, W - 6, "      " + c.dim) + c.reset);

  if (step.decision !== "operator") {
    const argStr = JSON.stringify(step.args ?? {});
    console.log(`      ${c.blue}→ ${step.server}__${step.tool}(${argStr.length > 62 ? argStr.slice(0, 62) + "…" : argStr})${c.reset}`);
  }

  const risk = `${stateColor(step.securityState)}${step.riskScore}/100${c.reset}`;
  const delta = step.riskDelta ? ` ${c.grey}(${step.riskDelta > 0 ? "+" : ""}${step.riskDelta})${c.reset}` : "";
  console.log(
    `      ${verdictBadge(step.decision)} risk ${risk}${delta} ` +
    `state ${stateColor(step.securityState)}${step.securityState}${c.reset} ` +
    `${c.grey}[${step.policy}]${c.reset}`
  );
  console.log(wrap(step.reason, W - 8, "        " + c.grey) + c.reset);

  for (const finding of step.semanticFindings) {
    console.log(`        ${c.yellow}⚑ ${finding}${c.reset}`);
  }

  const realFindings = step.driftFindings.filter((f) => f.type !== "BEHAVIOR_DRIFT");
  if (realFindings.length > 0) {
    console.log(`        ${c.red}⚠ ${realFindings.length} behavioural drift finding(s):${c.reset}`);
    for (const f of realFindings.slice(0, 5)) {
      console.log(`          ${c.red}• [${f.severity}] ${f.message}${c.reset}`);
    }
    if (realFindings.length > 5) {
      console.log(`          ${c.grey}… ${realFindings.length - 5} more${c.reset}`);
    }
  }

  if (step.stateTransition) {
    console.log(
      `        ${c.bold}STATE: ${stateColor(step.stateTransition.from)}${step.stateTransition.from}` +
      `${c.reset}${c.bold} → ${stateColor(step.stateTransition.to)}${step.stateTransition.to}${c.reset}`
    );
  }
  if (step.quarantined) {
    console.log(`        ${c.bgRed} SERVER QUARANTINED — ALL TOOL CALLS NOW HARD-BLOCKED ${c.reset}`);
  }
  if (step.expected && !step.met) {
    console.log(`        ${c.yellow}MISMATCH: scenario expected "${step.expected}", got "${step.decision}"${c.reset}`);
  }
}

function printSummary(run: ScenarioRunResult) {
  console.log(`\n${c.cyan}${rule()}${c.reset}`);
  console.log(
    `  ${c.bold}${run.name}${c.reset} — ` +
    `${c.green}${run.allowed} allowed${c.reset}, ` +
    `${c.red}${run.blocked} blocked${c.reset}, ` +
    `${c.yellow}${run.approvalsRequired} approval(s)${c.reset}, ` +
    `peak risk ${stateColor(run.finalState)}${run.peakRisk}/100${c.reset}, ` +
    `final ${stateColor(run.finalState)}${run.finalState}${c.reset}`
  );
  console.log(
    `  Expectations: ${run.expectationsMet ? `${c.green}all met${c.reset}` : `${c.red}MISMATCH${c.reset}`}` +
    ` ${c.grey}· ${run.durationMs}ms wall clock${c.reset}`
  );
  console.log(`${c.cyan}${rule()}${c.reset}`);
}

async function main() {
  const args = process.argv.slice(2);
  const withDashboard = args.includes("--dashboard");
  const runAll = args.includes("--all");
  const explicit = args.filter((a) => !a.startsWith("--"));

  banner(
    "MCP-SENTINEL — ADAPTIVE SECURITY CONTROL PLANE FOR MCP",
    "Live scenarios against real MCP server processes. No scripted outcomes."
  );

  const sentinel = new AdaptiveController({
    risk: {
      thresholds: { monitor: 26, restrict: 50, approval: 65, quarantine: 80 },
      weights: { integrity: 15, behavior: 30, runtime: 20, authorization: 15, sensitivity: 10, anomaly: 10 },
    },
  });

  const engine = new ScenarioEngine(sentinel, defaultFixtureSpecs(resolve(__dirname, "fixtures")));

  console.log(`  ${c.green}✓${c.reset} Identity verifier, semantic firewall, lease manager`);
  console.log(`  ${c.green}✓${c.reset} Contextual tool-call engine, data-flow taint guard`);
  console.log(`  ${c.green}✓${c.reset} Behaviour fingerprinting, deterministic risk engine, state machine`);
  console.log(`  ${c.green}✓${c.reset} Quarantine manager, SHA-256 decision receipts ledger`);

  let dashboard: { close: () => Promise<void> } | null = null;
  if (withDashboard) {
    try {
      dashboard = await startDashboard({
        port: 3100,
        auditLogPath: resolve(__dirname, "demo-audit.jsonl"),
        getStatus: () => ({ servers: [], rateLimits: [] }),
        sentinel,
        scenarioEngine: engine,
      });
      console.log(`  ${c.green}✓${c.reset} Live console: ${c.cyan}http://localhost:3100${c.reset}`);
    } catch (err) {
      console.log(`  ${c.yellow}! Console unavailable: ${err instanceof Error ? err.message : err}${c.reset}`);
    }
  }

  const ids = explicit.length > 0
    ? explicit
    : runAll
      ? engine.listScenarios().map((s) => s.id)
      : ["rug-pull"];

  const runs: ScenarioRunResult[] = [];

  for (const id of ids) {
    const scenario = engine.getScenario(id);
    if (!scenario) {
      console.log(`\n${c.red}Unknown scenario "${id}". Available: ${engine.listScenarios().map((s) => s.id).join(", ")}${c.reset}`);
      continue;
    }

    // Each scenario starts from a genuinely clean control plane.
    await engine.reset();

    banner(scenario.name, scenario.technique);
    console.log(wrap(scenario.summary, W - 2, "  " + c.dim) + c.reset);
    console.log(`\n  ${c.bold}Expected:${c.reset} ${c.dim}${scenario.expectedOutcome}${c.reset}`);
    console.log(`  ${c.grey}${rule()}${c.reset}`);

    engine.onStep(printStep);
    const run = await engine.run(id);
    runs.push(run);
    printSummary(run);
  }

  if (runs.length > 1) {
    banner("SUMMARY");
    console.log(`  ${"Scenario".padEnd(30)}${"Blocked".padEnd(10)}${"Approvals".padEnd(12)}${"Peak".padEnd(8)}Result`);
    console.log(`  ${c.grey}${rule()}${c.reset}`);
    for (const run of runs) {
      console.log(
        `  ${run.name.slice(0, 28).padEnd(30)}` +
        `${String(run.blocked).padEnd(10)}` +
        `${String(run.approvalsRequired).padEnd(12)}` +
        `${String(run.peakRisk).padEnd(8)}` +
        (run.expectationsMet ? `${c.green}PASS${c.reset}` : `${c.red}MISMATCH${c.reset}`)
      );
    }
    console.log();
  }

  const allMet = runs.every((r) => r.expectationsMet);
  console.log(
    allMet
      ? `\n  ${c.green}${c.bold}All scenario expectations met.${c.reset}\n`
      : `\n  ${c.red}${c.bold}One or more scenarios did not meet expectations.${c.reset}\n`
  );

  if (withDashboard) {
    console.log(`  ${c.cyan}Console still serving on http://localhost:3100 — Ctrl-C to exit.${c.reset}\n`);
    await new Promise(() => {});
  }

  await engine.shutdown();
  await dashboard?.close();
  process.exit(allMet ? 0 : 1);
}

main().catch((err) => {
  console.error(`\n${c.red}Demo failed:${c.reset}`, err);
  process.exit(1);
});
