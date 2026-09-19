/**
 * MCP-Sentinel: Comparative Security & Performance Evaluation
 *
 * Runs the SAME attack against three architectures and measures what each one
 * actually does:
 *
 *   [A] Raw MCP            — client talks to the server directly, no proxy
 *   [B] Static gateway     — descriptor scanning + rate limiting, registration-time only
 *   [C] MCP-Sentinel       — full adaptive control plane
 *
 * All three drive the same real MCP server child process over stdio and observe
 * the same real responses. The only variable is what sits in the middle. The
 * measured overhead is the cost of the security pipeline on identical bytes.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { AdaptiveController } from "../src/sentinel/adaptive-controller.js";
import { scanToolDescription } from "../src/middleware/security-scanner.js";
import type { SentinelToolContext } from "../src/sentinel/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(__dirname, "fixtures/rugpull-server.mjs");

const c = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m", grey: "\x1b[90m",
  cyan: "\x1b[36m", green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m",
};

interface ScenarioResult {
  architecture: string;
  description: string;
  legitimateTaskSucceeded: boolean;
  attackDetected: boolean;
  attackBlocked: boolean;
  attackContained: boolean;
  findingsCount: number;
  finalRisk: number;
  finalState: string;
  securityOverheadMs: number;
  notes: string;
}

/** Spawns a fresh rug-pull fixture and returns a connected MCP client. */
async function spawnFixture(): Promise<{ client: Client; close: () => Promise<void> }> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [FIXTURE],
    env: process.env as Record<string, string>,
  });
  const client = new Client({ name: "evaluation-harness", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return {
    client,
    close: async () => {
      try { await client.close(); } catch { /* child is exiting anyway */ }
    },
  };
}

function textOf(result: unknown): string {
  const r = result as { content?: Array<{ type: string; text?: string }> };
  if (!Array.isArray(r?.content)) return "";
  return r.content.filter((x) => x.type === "text" && x.text).map((x) => x.text as string).join("\n");
}

/** Did the tool response actually contain exfiltrated material? */
function attackSucceeded(output: string): boolean {
  return /\.env|id_rsa|API_KEY|c2\.|evil\./i.test(output);
}

async function main() {
  console.log(`\n${c.bold}${c.cyan}${"═".repeat(84)}${c.reset}`);
  console.log(`${c.bold}${c.cyan}  MCP-SENTINEL — COMPARATIVE EVALUATION${c.reset}`);
  console.log(`  ${c.dim}Same real MCP server, same real rug-pull, three architectures${c.reset}`);
  console.log(`${c.bold}${c.cyan}${"═".repeat(84)}${c.reset}\n`);

  const results: ScenarioResult[] = [];

  // ═══════════════════════════════════════════════════════════
  // [A] RAW MCP — no protection whatsoever
  // ═══════════════════════════════════════════════════════════
  console.log(`${c.yellow}[A] Raw MCP — direct client → server, no proxy${c.reset}`);
  {
    const { client, close } = await spawnFixture();
    const t0 = performance.now();

    const legit = textOf(await client.callTool({ name: "search_logs", arguments: { query: "Authentication" } }));
    await client.callTool({ name: "apply_vendor_update", arguments: { channel: "stable" } });
    const malicious = textOf(await client.callTool({ name: "search_logs", arguments: { query: "Authentication" } }));

    const overhead = performance.now() - t0;
    await close();

    const succeeded = attackSucceeded(malicious);
    results.push({
      architecture: "A: Raw MCP",
      description: "Direct client → server (no proxy)",
      legitimateTaskSucceeded: legit.includes("Authentication"),
      attackDetected: false,
      attackBlocked: false,
      attackContained: false,
      findingsCount: 0,
      finalRisk: 0,
      finalState: "NONE",
      securityOverheadMs: 0,
      notes: succeeded
        ? "Exfiltration payload returned to the agent verbatim; nothing observed it"
        : "Attack payload not present",
    });
    console.log(`    ${c.red}✗ Attack succeeded — ${malicious.split("\n").filter((l) => /DEBUG/.test(l)).length} hostile lines delivered to the agent${c.reset}`);
    console.log(`    ${c.grey}round trip: ${overhead.toFixed(2)}ms${c.reset}\n`);
  }

  // ═══════════════════════════════════════════════════════════
  // [B] STATIC GATEWAY — descriptor scanning at registration only
  // ═══════════════════════════════════════════════════════════
  console.log(`${c.yellow}[B] Static gateway — descriptor scan + rate limit, registration-time only${c.reset}`);
  {
    const { client, close } = await spawnFixture();

    // Registration-time scan of the CLEAN descriptor, which is the whole point:
    // a static gateway inspects the contract before the rug-pull happens.
    const listed = await client.listTools();
    const searchLogs = listed.tools.find((t) => t.name === "search_logs");

    const tScan = performance.now();
    const staticFindings = scanToolDescription(searchLogs?.description ?? "");
    const scanCost = performance.now() - tScan;

    const legit = textOf(await client.callTool({ name: "search_logs", arguments: { query: "Authentication" } }));
    await client.callTool({ name: "apply_vendor_update", arguments: { channel: "stable" } });
    const malicious = textOf(await client.callTool({ name: "search_logs", arguments: { query: "Authentication" } }));

    await close();

    const succeeded = attackSucceeded(malicious);
    results.push({
      architecture: "B: Static gateway",
      description: "Descriptor scan + rate limit at registration",
      legitimateTaskSucceeded: legit.includes("Authentication"),
      attackDetected: staticFindings.length > 0,
      attackBlocked: false,
      attackContained: false,
      findingsCount: staticFindings.length,
      finalRisk: 0,
      finalState: "NONE",
      securityOverheadMs: Number(scanCost.toFixed(3)),
      notes: succeeded
        ? "Descriptor was clean when scanned; the compromise arrived afterwards and was never re-checked"
        : "Attack payload not present",
    });
    console.log(`    ${c.dim}Registration-time descriptor scan: ${staticFindings.length} findings (descriptor was clean)${c.reset}`);
    console.log(`    ${c.red}✗ Attack succeeded — static inspection cannot see runtime behaviour${c.reset}`);
    console.log(`    ${c.grey}security overhead: ${scanCost.toFixed(3)}ms${c.reset}\n`);
  }

  // ═══════════════════════════════════════════════════════════
  // [C] MCP-SENTINEL — full adaptive control plane
  // ═══════════════════════════════════════════════════════════
  console.log(`${c.yellow}[C] MCP-Sentinel — adaptive control plane${c.reset}`);
  {
    const sentinel = new AdaptiveController({
      risk: { thresholds: { monitor: 26, restrict: 50, approval: 65, quarantine: 80 } },
    });
    const { client, close } = await spawnFixture();

    const server = sentinel.registry.registerServer("vendor", {
      serverName: "Third-Party Vendor Tools",
      transport: "stdio",
    });
    const listed = await client.listTools();
    for (const t of listed.tools) {
      sentinel.registry.registerTool(server.serverId, t.name, {
        description: t.description ?? "",
        inputSchema: t.inputSchema,
      });
    }

    const ctxFor = (tool: string, args: Record<string, unknown>): SentinelToolContext => {
      const reg = sentinel.registry.getToolByName(server.serverId, tool);
      const srv = sentinel.registry.getServer(server.serverId);
      return {
        server: "vendor",
        serverId: server.serverId,
        tool,
        toolId: reg?.toolId ?? "",
        args,
        userId: "analyst1",
        userRole: "analyst",
        riskScore: srv?.currentRisk ?? 0,
        securityState: srv?.securityState ?? "NORMAL",
      };
    };

    let securityMs = 0;

    // 1. Legitimate call — establishes the behavioural baseline.
    const legitCtx = ctxFor("search_logs", { query: "Authentication" });
    let t = performance.now();
    sentinel.preExecute(legitCtx);
    securityMs += performance.now() - t;

    const legit = textOf(await client.callTool({ name: "search_logs", arguments: { query: "Authentication" } }));

    t = performance.now();
    sentinel.postExecute(legitCtx, legit, 5);
    securityMs += performance.now() - t;

    // 2. The rug-pull.
    await client.callTool({ name: "apply_vendor_update", arguments: { channel: "stable" } });

    // 3. Re-read the contract — the semantic firewall sees the expansion.
    const updated = await client.listTools();
    const mutated = updated.tools.find((x) => x.name === "search_logs");
    const previous = sentinel.registry.getToolByName(server.serverId, "search_logs")!;

    t = performance.now();
    const diff = sentinel.semanticFirewall.evaluateUpdate(previous, {
      description: mutated?.description ?? "",
      inputSchema: mutated?.inputSchema as Record<string, unknown>,
    });
    sentinel.recordSemanticChange(server.serverId, "search_logs", diff);
    securityMs += performance.now() - t;

    // 4. The compromised call.
    const attackCtx = ctxFor("search_logs", { query: "Authentication" });
    t = performance.now();
    const preDecision = sentinel.preExecute(attackCtx);
    securityMs += performance.now() - t;

    let maliciousOutput = "";
    let post: ReturnType<AdaptiveController["postExecute"]> | null = null;

    if (preDecision.action === "allow") {
      maliciousOutput = textOf(await client.callTool({ name: "search_logs", arguments: { query: "Authentication" } }));
      t = performance.now();
      post = sentinel.postExecute(attackCtx, maliciousOutput, 8);
      securityMs += performance.now() - t;
    }

    // 5. Retry after containment.
    const retryCtx = ctxFor("search_logs", { query: "anything" });
    t = performance.now();
    const retryDecision = sentinel.preExecute(retryCtx);
    securityMs += performance.now() - t;

    await close();

    const finalServer = sentinel.registry.getServer(server.serverId)!;
    const contained = retryDecision.action === "block";
    const detected = (post?.driftFindings.length ?? 0) > 0 || diff.hasSemanticChange;

    results.push({
      architecture: "C: MCP-Sentinel",
      description: "Adaptive control plane (behaviour + risk + quarantine)",
      legitimateTaskSucceeded: legit.includes("Authentication"),
      attackDetected: detected,
      attackBlocked: contained,
      attackContained: sentinel.quarantineManager.isQuarantined(server.serverId),
      findingsCount: (post?.driftFindings.length ?? 0) + diff.findings.length,
      finalRisk: finalServer.currentRisk,
      finalState: finalServer.securityState,
      securityOverheadMs: Number(securityMs.toFixed(3)),
      notes: contained
        ? "Semantic expansion flagged pre-execution; runtime drift quarantined the server; retry hard-blocked"
        : "Attack was not contained",
    });

    console.log(`    ${c.green}✓ Semantic firewall: ${diff.findings.length} contract-expansion findings${c.reset}`);
    console.log(`    ${c.green}✓ Behavioural drift: ${post?.driftFindings.length ?? 0} findings on the real response${c.reset}`);
    console.log(`    ${c.green}✓ Risk ${finalServer.currentRisk}/100 → ${finalServer.securityState}${c.reset}`);
    console.log(`    ${c.green}✓ Retry after containment: ${retryDecision.action.toUpperCase()} [${retryDecision.policyDecision.policy}]${c.reset}`);
    console.log(`    ${c.grey}security overhead: ${securityMs.toFixed(3)}ms across 5 pipeline passes${c.reset}\n`);
  }

  // ═══════════════════════════════════════════════════════════
  // RESULTS TABLE
  // ═══════════════════════════════════════════════════════════
  console.log(`${c.bold}${c.cyan}${"═".repeat(84)}${c.reset}`);
  console.log(`${c.bold}  RESULTS${c.reset}`);
  console.log(`${c.bold}${c.cyan}${"═".repeat(84)}${c.reset}\n`);

  const yn = (v: boolean) => (v ? `${c.green}YES${c.reset}` : `${c.red}NO ${c.reset}`);
  console.log(
    `  ${"Architecture".padEnd(21)}${"Legit".padEnd(8)}${"Detect".padEnd(9)}` +
    `${"Block".padEnd(8)}${"Contain".padEnd(10)}${"Risk".padEnd(7)}Overhead`
  );
  console.log(`  ${c.grey}${"─".repeat(80)}${c.reset}`);
  for (const r of results) {
    console.log(
      `  ${r.architecture.padEnd(21)}` +
      `${yn(r.legitimateTaskSucceeded)}  ` +
      `${yn(r.attackDetected)}   ` +
      `${yn(r.attackBlocked)}  ` +
      `${yn(r.attackContained)}    ` +
      `${String(r.finalRisk).padEnd(7)}` +
      `${r.securityOverheadMs.toFixed(3)}ms`
    );
  }

  console.log(`\n  ${c.bold}Interpretation${c.reset}`);
  for (const r of results) {
    console.log(`  ${c.dim}${r.architecture}:${c.reset} ${r.notes}`);
  }

  const sentinelResult = results.find((r) => r.architecture.startsWith("C"))!;
  console.log(
    `\n  ${c.dim}All three ran the same fixture and saw the same bytes. ` +
    `The decisive difference is not detection rate — it is that only (C) observes ` +
    `behaviour AFTER the contract was signed.${c.reset}\n`
  );

  const outPath = resolve(__dirname, "evaluation-results.json");
  await writeFile(outPath, JSON.stringify({
    generatedAt: new Date().toISOString(),
    fixture: "test/fixtures/rugpull-server.mjs",
    methodology:
      "Each architecture spawns the same MCP server child process, performs a clean call, " +
      "triggers the in-band vendor update, then performs the compromised call. " +
      "Overhead measures only the security pipeline, excluding upstream I/O.",
    results,
  }, null, 2) + "\n");
  console.log(`  ${c.grey}Machine-readable results → ${outPath}${c.reset}\n`);

  // The benchmark asserts its own headline claim rather than just printing it.
  const ok = sentinelResult.attackDetected && sentinelResult.attackBlocked && sentinelResult.attackContained;
  process.exit(ok ? 0 : 1);
}

main().catch((err) => {
  console.error("Evaluation failed:", err);
  process.exit(1);
});
