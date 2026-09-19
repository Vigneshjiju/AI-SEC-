import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AdaptiveController } from "../sentinel/adaptive-controller.js";
import type { ScenarioEngine, ScenarioStepResult, ScenarioRunResult } from "../sentinel/scenario-engine.js";
import type { SecurityEvent, CapabilitySet, BehaviorFingerprint } from "../sentinel/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface DashboardOptions {
  port: number;
  auditLogPath: string;
  getStatus: () => {
    servers: Array<{ name: string; tools: number }>;
    rateLimits: Array<{ tool: string; count: number; limit: number }>;
  };
  getSentinel?: () => AdaptiveController | null;
  sentinel?: AdaptiveController | null;
  scenarioEngine?: ScenarioEngine | null;
}

export interface DashboardHandle {
  port: number;
  close: () => Promise<void>;
}

function parseBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

function setCors(res: ServerResponse) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function sendJson(res: ServerResponse, status: number, data: unknown) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  setCors(res);
  res.end(JSON.stringify(data));
}

// ── Presentation helpers (computed server-side so the UI stays a pure view) ──

function capabilitySetToTags(caps: CapabilitySet | null | undefined): string[] {
  if (!caps) return [];
  const tags: string[] = [];
  for (const path of caps.filesystem) tags.push(`fs:${path}`);
  for (const host of caps.network) tags.push(`net:${host}`);
  for (const proc of caps.processes) tags.push(`proc:${proc}`);
  if (caps.envAccess) tags.push("env_access");
  if (caps.externalNetwork) tags.push("external_network");
  if (caps.sensitiveFileAccess) tags.push("sensitive_files");
  if (caps.commandExecution) tags.push("command_execution");
  return tags;
}

function fingerprintToTags(fp: BehaviorFingerprint | null | undefined): string[] {
  if (!fp) return [];
  const tags: string[] = [];
  for (const path of fp.filesystem.slice(0, 6)) tags.push(`fs:${path}`);
  for (const host of fp.network.slice(0, 6)) tags.push(`net:${host}`);
  for (const proc of fp.processes.slice(0, 4)) tags.push(`proc:${proc}`);
  if (fp.envAccess) tags.push("env_access");
  if (fp.externalNetwork) tags.push("external_network");
  if (fp.sensitiveFileAccess) tags.push("sensitive_files");
  if (fp.commandExecution) tags.push("command_execution");
  return tags;
}

/**
 * Builds the tool view the dashboard renders.
 *
 * Observed capability is deliberately reported as an empty list when no
 * fingerprint exists yet. Falling back to the declared set (as an earlier
 * version did) shows operators "observed" capabilities that were never
 * observed, which is precisely the claim this product exists to disprove.
 */
function buildToolView(sentinel: AdaptiveController) {
  return sentinel.registry.getAllTools().map((tool) => {
    const server = sentinel.registry.getServer(tool.serverId);
    const declaredTags = capabilitySetToTags(tool.declaredCapabilities);
    const authorizedTags = capabilitySetToTags(tool.authorizedCapabilities);
    const observedTags = fingerprintToTags(tool.currentFingerprint);

    const driftFindings =
      tool.currentFingerprint && tool.baselineFingerprint
        ? sentinel.behaviorEngine.compareFingerprint(
            tool.baselineFingerprint,
            tool.currentFingerprint,
            tool.declaredCapabilities,
            tool.authorizedCapabilities,
          )
        : [];

    // Semantic comparison — not tag string equality. A private-range host is
    // not external egress, and "*" scope means declared-but-unconstrained.
    const conformance = tool.currentFingerprint
      ? sentinel.behaviorEngine.assessConformance(tool.currentFingerprint, tool.authorizedCapabilities)
      : { violations: [], reasons: [] };

    return {
      toolId: tool.toolId,
      toolName: tool.toolName,
      serverId: tool.serverId,
      serverName: server?.serverName ?? "unknown",
      description: tool.description,
      riskScore: tool.riskScore,
      state: tool.state,
      callCount: tool.callCount,
      lastCalledAt: tool.lastCalledAt,
      criticality: tool.criticality,
      sensitivity: tool.sensitivity,
      annotations: tool.annotations ?? null,
      hasBaseline: tool.baselineFingerprint !== null,
      declaredCapabilities: declaredTags,
      authorizedCapabilities: authorizedTags,
      observedCapabilities: observedTags,
      unauthorizedCapabilities: conformance.violations,
      conformanceReasons: conformance.reasons,
      hasDrift: driftFindings.length > 0,
      driftFindings,
      semanticChanges: tool.semanticChanges ?? [],
    };
  });
}

function buildServerView(sentinel: AdaptiveController) {
  return sentinel.registry.getAllServers().map((s) => ({
    ...s,
    quarantined: sentinel.registry.isQuarantined(s.serverId),
    toolCount: s.toolIds.length,
  }));
}

export async function startDashboard(opts: DashboardOptions): Promise<DashboardHandle> {
  const htmlPath = resolve(__dirname, "index.html");
  let htmlContent: string;

  try {
    htmlContent = await readFile(htmlPath, "utf-8");
  } catch {
    const srcHtmlPath = resolve(__dirname, "../../src/dashboard/index.html");
    htmlContent = await readFile(srcHtmlPath, "utf-8");
  }

  // ── Server-Sent Events fan-out ──
  const sseClients = new Set<ServerResponse>();

  function broadcast(type: string, payload: unknown) {
    const frame = `event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(frame);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  const resolveSentinel = () => opts.sentinel ?? (opts.getSentinel ? opts.getSentinel() : null);

  // Subscribe once to the live security event bus. Every decision the control
  // plane makes is pushed to connected dashboards immediately rather than
  // waiting for the next poll tick.
  let subscribedTo: AdaptiveController | null = null;
  function ensureSubscribed() {
    const sentinel = resolveSentinel();
    if (!sentinel || sentinel === subscribedTo) return sentinel;
    sentinel.eventBus.on("*", (event: SecurityEvent) => {
      broadcast("security-event", event);
      broadcast("overview", sentinel.getSystemOverview());
    });
    subscribedTo = sentinel;
    return sentinel;
  }
  ensureSubscribed();

  if (opts.scenarioEngine) {
    opts.scenarioEngine.onStep((step: ScenarioStepResult) => broadcast("scenario-step", step));
    opts.scenarioEngine.onRunComplete((run: ScenarioRunResult) => broadcast("scenario-complete", run));
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${opts.port}`);

    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      setCors(res);
      res.end();
      return;
    }

    const sentinel = ensureSubscribed();
    const scenarioEngine = opts.scenarioEngine ?? null;

    // ══════════════════════════════════════════════
    // LIVE EVENT STREAM (SSE)
    // ══════════════════════════════════════════════
    if (url.pathname === "/api/sentinel/stream" || url.pathname === "/api/stream") {
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      setCors(res);
      res.write(": connected\n\n");

      if (sentinel) {
        res.write(`event: overview\ndata: ${JSON.stringify(sentinel.getSystemOverview())}\n\n`);
      }

      sseClients.add(res);

      // Keep intermediaries from closing an idle stream.
      const heartbeat = setInterval(() => {
        try {
          res.write(": ping\n\n");
        } catch {
          clearInterval(heartbeat);
          sseClients.delete(res);
        }
      }, 15000);

      req.on("close", () => {
        clearInterval(heartbeat);
        sseClients.delete(res);
      });
      return;
    }

    // ══════════════════════════════════════════════
    // SCENARIO CONTROL
    // ══════════════════════════════════════════════
    if (url.pathname === "/api/sentinel/scenarios" || url.pathname === "/api/scenarios") {
      if (!scenarioEngine) {
        sendJson(res, 200, { scenarios: [], available: false });
        return;
      }
      sendJson(res, 200, {
        available: true,
        running: scenarioEngine.isRunning(),
        lastRun: scenarioEngine.getLastRun(),
        scenarios: scenarioEngine.listScenarios(),
      });
      return;
    }

    const scenarioDetail = url.pathname.match(/^\/api\/(?:sentinel\/)?scenarios\/([^/]+)$/);
    if (scenarioDetail && req.method === "GET") {
      if (!scenarioEngine) {
        sendJson(res, 400, { error: "Scenario engine not enabled" });
        return;
      }
      const scenario = scenarioEngine.getScenario(scenarioDetail[1]);
      if (!scenario) {
        sendJson(res, 404, { error: `Unknown scenario "${scenarioDetail[1]}"` });
        return;
      }
      sendJson(res, 200, scenario);
      return;
    }

    const scenarioRun = url.pathname.match(/^\/api\/(?:sentinel\/)?scenarios\/([^/]+)\/run$/);
    if (scenarioRun && req.method === "POST") {
      if (!scenarioEngine) {
        sendJson(res, 400, { error: "Scenario engine not enabled" });
        return;
      }
      if (scenarioEngine.isRunning()) {
        sendJson(res, 409, { error: "A scenario is already running" });
        return;
      }
      const scenarioId = scenarioRun[1];
      if (!scenarioEngine.getScenario(scenarioId)) {
        sendJson(res, 404, { error: `Unknown scenario "${scenarioId}"` });
        return;
      }

      // Respond immediately; progress arrives over the SSE stream.
      sendJson(res, 202, { started: true, scenarioId });
      scenarioEngine.run(scenarioId).catch((err) => {
        broadcast("scenario-error", {
          scenarioId,
          error: err instanceof Error ? err.message : String(err),
        });
      });
      return;
    }

    if (
      (url.pathname === "/api/sentinel/scenarios/reset" || url.pathname === "/api/scenarios/reset") &&
      req.method === "POST"
    ) {
      if (!scenarioEngine) {
        sendJson(res, 400, { error: "Scenario engine not enabled" });
        return;
      }
      await scenarioEngine.reset();
      broadcast("reset", { timestamp: new Date().toISOString() });
      if (sentinel) broadcast("overview", sentinel.getSystemOverview());
      sendJson(res, 200, { success: true, message: "Control plane reset to a clean baseline" });
      return;
    }

    // ══════════════════════════════════════════════
    // TELEMETRY
    // ══════════════════════════════════════════════

    if (url.pathname === "/api/status") {
      try {
        const logContent = await readFile(opts.auditLogPath, "utf-8").catch(() => "");
        const entries = logContent
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((line) => {
            try {
              return JSON.parse(line);
            } catch {
              return null;
            }
          })
          .filter(Boolean);

        const status = opts.getStatus();
        sendJson(res, 200, {
          entries,
          servers: status.servers,
          rateLimits: status.rateLimits,
          sentinel: sentinel ? sentinel.getSystemOverview() : null,
        });
      } catch {
        sendJson(res, 500, { error: "Failed to read audit log" });
      }
      return;
    }

    if (url.pathname === "/api/sentinel/state" || url.pathname === "/api/state") {
      sendJson(res, 200, sentinel ? sentinel.getSystemOverview() : { status: "Sentinel not enabled" });
      return;
    }

    if (url.pathname === "/api/sentinel/servers" || url.pathname === "/api/servers") {
      sendJson(res, 200, sentinel ? buildServerView(sentinel) : []);
      return;
    }

    if (url.pathname === "/api/sentinel/tools" || url.pathname === "/api/tools") {
      sendJson(res, 200, sentinel ? buildToolView(sentinel) : []);
      return;
    }

    if (url.pathname === "/api/sentinel/events" || url.pathname === "/api/events") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      const limit = parseInt(url.searchParams.get("limit") ?? "100", 10);
      sendJson(res, 200, sentinel.eventBus.getEvents(limit));
      return;
    }

    if (url.pathname === "/api/sentinel/timeline" || url.pathname === "/api/timeline") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      sendJson(res, 200, sentinel.riskEngine.getTimeline(300));
      return;
    }

    if (url.pathname === "/api/sentinel/transitions") {
      sendJson(res, 200, sentinel ? sentinel.stateMachine.getTransitions(100) : []);
      return;
    }

    if (url.pathname === "/api/sentinel/quarantines") {
      sendJson(res, 200, sentinel ? sentinel.quarantineManager.getHistory() : []);
      return;
    }

    if (url.pathname === "/api/sentinel/approvals" || url.pathname === "/api/approvals") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      sendJson(res, 200, url.searchParams.get("all") === "true"
        ? sentinel.policyEngine.getAllApprovals()
        : sentinel.policyEngine.getPendingApprovals());
      return;
    }

    if (url.pathname === "/api/sentinel/receipts" || url.pathname === "/api/receipts") {
      sendJson(res, 200, sentinel ? sentinel.receiptsLedger.getAllReceipts() : []);
      return;
    }

    if (url.pathname === "/api/sentinel/leases" || url.pathname === "/api/leases") {
      sendJson(res, 200, sentinel ? sentinel.leaseManager.getActiveLeases() : []);
      return;
    }

    if (url.pathname === "/api/sentinel/grants") {
      if (!sentinel) {
        sendJson(res, 200, { jit: [], approvals: [] });
        return;
      }
      sendJson(res, 200, {
        jit: sentinel.authManager.getAllActiveGrants(),
        approvals: sentinel.policyEngine.getOpenGrants(),
      });
      return;
    }

    if (url.pathname === "/api/sentinel/workflows") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      sendJson(res, 200, sentinel.contextualEngine.getAllWorkflows().map((w) => ({
        workflowId: w.workflowId,
        userId: w.userId,
        agentId: w.agentId,
        intent: w.intent,
        capabilityHistory: w.capabilityHistory,
        toolCallHistory: w.toolCallHistory.map((t) => ({
          toolName: t.toolName,
          server: t.server,
          capability: t.capability,
          decision: t.decision,
          riskScore: t.riskScore,
          timestamp: t.timestamp,
        })),
        riskScore: w.riskScore,
        updatedAt: w.updatedAt,
      })));
      return;
    }

    // ══════════════════════════════════════════════
    // CONTROL ACTIONS
    // ══════════════════════════════════════════════

    const approveMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?approvals?\/([^/]+)\/approve$/);
    if (approveMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const body = await parseBody(req);
      const result = sentinel.approveRequest(approveMatch[1], body.decidedBy || "operator");
      if (!result) {
        sendJson(res, 404, { error: `Approval request ${approveMatch[1]} not found or not pending` });
        return;
      }
      sendJson(res, 200, { success: true, approval: result });
      return;
    }

    const denyMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?approvals?\/([^/]+)\/deny$/);
    if (denyMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const body = await parseBody(req);
      const result = sentinel.denyRequest(denyMatch[1], body.decidedBy || "operator");
      if (!result) {
        sendJson(res, 404, { error: `Approval request ${denyMatch[1]} not found or not pending` });
        return;
      }
      sendJson(res, 200, { success: true, approval: result });
      return;
    }

    const quarantineMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?servers?\/([^/]+)\/quarantine$/);
    if (quarantineMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const body = await parseBody(req);
      const record = sentinel.quarantineManager.quarantine(
        quarantineMatch[1],
        body.reason || "Manual quarantine triggered from the dashboard",
        100,
        [body.reason || "Operator-initiated containment"],
        "manual_operator_action",
      );
      if (!record) {
        sendJson(res, 404, { error: `Server ${quarantineMatch[1]} not found` });
        return;
      }
      sendJson(res, 200, { success: true, record });
      return;
    }

    const recoverMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?servers?\/([^/]+)\/recover$/);
    if (recoverMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const body = await parseBody(req);
      const ok = sentinel.quarantineManager.recover(
        recoverMatch[1],
        body.approvedBy || "operator",
        body.reason,
      );
      if (!ok) {
        sendJson(res, 400, { error: `Server ${recoverMatch[1]} is not quarantined or not found` });
        return;
      }
      sendJson(res, 200, { success: true, message: `Server recovered to MONITOR state` });
      return;
    }

    if (url.pathname === "/api/sentinel/grants" && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const body = await parseBody(req);
      const grant = sentinel.authManager.grantTemporaryPermission(
        body.userId || "analyst1",
        Array.isArray(body.permissions) ? body.permissions : [],
        Number(body.ttlSeconds ?? 300),
        body.reason || "Operator-issued elevation",
      );
      sendJson(res, 200, { success: true, grant });
      return;
    }

    // ── Serve the dashboard ──
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(htmlContent);
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(opts.port, () => {
      server.off("error", rejectListen);
      process.stderr.write(`[mcp-sentinel] Security Dashboard: http://localhost:${opts.port}\n`);
      resolveListen();
    });
  });

  return {
    port: opts.port,
    close: () =>
      new Promise<void>((resolveClose) => {
        for (const client of sseClients) {
          try {
            client.end();
          } catch {
            /* already gone */
          }
        }
        sseClients.clear();
        server.close(() => resolveClose());
      }),
  };
}
