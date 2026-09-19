import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { AdaptiveController } from "../sentinel/adaptive-controller.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface DashboardOptions {
  port: number;
  auditLogPath: string;
  getStatus: () => {
    servers: Array<{ name: string; tools: number }>;
    rateLimits: Array<{ tool: string; count: number; limit: number }>;
  };
  getSentinel?: () => AdaptiveController | null;
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

function sendJson(res: ServerResponse, status: number, data: any) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.end(JSON.stringify(data));
}

export async function startDashboard(opts: DashboardOptions): Promise<void> {
  const htmlPath = resolve(__dirname, "index.html");
  let htmlContent: string;

  try {
    htmlContent = await readFile(htmlPath, "utf-8");
  } catch {
    const srcHtmlPath = resolve(__dirname, "../../src/dashboard/index.html");
    htmlContent = await readFile(srcHtmlPath, "utf-8");
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${opts.port}`);

    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.end();
      return;
    }

    const sentinel = opts.getSentinel ? opts.getSentinel() : null;

    // ── Existing Status Endpoint (Preserved + Extended) ──
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
        const overview = sentinel ? sentinel.getSystemOverview() : null;

        sendJson(res, 200, {
          entries,
          servers: status.servers,
          rateLimits: status.rateLimits,
          sentinel: overview,
        });
      } catch (err) {
        sendJson(res, 500, { error: "Failed to read audit log" });
      }
      return;
    }

    // ── Sentinel System State Overview ──
    if (url.pathname === "/api/sentinel/state" || url.pathname === "/api/state") {
      if (!sentinel) {
        sendJson(res, 200, { status: "Sentinel not enabled" });
        return;
      }
      sendJson(res, 200, sentinel.getSystemOverview());
      return;
    }

    // ── Sentinel Server Registry ──
    if (url.pathname === "/api/sentinel/servers" || url.pathname === "/api/servers") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      const servers = sentinel.registry.getAllServers();
      sendJson(res, 200, servers);
      return;
    }

    // ── Sentinel Tool Registry ──
    if (url.pathname === "/api/sentinel/tools" || url.pathname === "/api/tools") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      const tools = sentinel.registry.getAllTools();
      sendJson(res, 200, tools);
      return;
    }

    // ── Sentinel Security Events Feed ──
    if (url.pathname === "/api/sentinel/events" || url.pathname === "/api/events") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      const limit = parseInt(url.searchParams.get("limit") ?? "50", 10);
      const events = sentinel.eventBus.getEvents(limit);
      sendJson(res, 200, events);
      return;
    }

    // ── Sentinel Timeline ──
    if (url.pathname === "/api/sentinel/timeline" || url.pathname === "/api/timeline") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      const events = sentinel.eventBus.getEvents(200);
      const timeline = events.map((e) => ({
        id: e.id,
        timestamp: e.timestamp,
        server: e.serverName,
        tool: e.toolName,
        type: e.type,
        riskScore: e.riskScore,
        state: e.securityState,
        decision: e.decision,
        reasons: e.reasons,
      }));
      sendJson(res, 200, timeline);
      return;
    }

    // ── Sentinel Pending Approvals ──
    if (url.pathname === "/api/sentinel/approvals" || url.pathname === "/api/approvals") {
      if (!sentinel) {
        sendJson(res, 200, []);
        return;
      }
      sendJson(res, 200, sentinel.policyEngine.getPendingApprovals());
      return;
    }

    // ── POST: Approve Request ──
    const approveMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?approvals?\/([^/]+)\/approve$/);
    if (approveMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const id = approveMatch[1];
      const body = await parseBody(req);
      const approvedBy = body.decidedBy || "admin";
      const result = sentinel.policyEngine.approveRequest(id, approvedBy);
      if (!result) {
        sendJson(res, 404, { error: `Approval request ${id} not found or not pending` });
        return;
      }
      sendJson(res, 200, { success: true, approval: result });
      return;
    }

    // ── POST: Deny Request ──
    const denyMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?approvals?\/([^/]+)\/deny$/);
    if (denyMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const id = denyMatch[1];
      const body = await parseBody(req);
      const deniedBy = body.decidedBy || "admin";
      const result = sentinel.policyEngine.denyRequest(id, deniedBy);
      if (!result) {
        sendJson(res, 404, { error: `Approval request ${id} not found or not pending` });
        return;
      }
      sendJson(res, 200, { success: true, approval: result });
      return;
    }

    // ── POST: Quarantine Server ──
    const quarantineMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?servers?\/([^/]+)\/quarantine$/);
    if (quarantineMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const serverId = quarantineMatch[1];
      const body = await parseBody(req);
      const reason = body.reason || "Manual quarantine triggered via dashboard";
      const record = sentinel.quarantineManager.quarantine(
        serverId,
        reason,
        100,
        [reason],
        "manual_operator_action"
      );
      if (!record) {
        sendJson(res, 404, { error: `Server ${serverId} not found` });
        return;
      }
      sendJson(res, 200, { success: true, record });
      return;
    }

    // ── POST: Recover Server ──
    const recoverMatch = url.pathname.match(/^\/api\/(?:sentinel\/)?servers?\/([^/]+)\/recover$/);
    if (recoverMatch && req.method === "POST") {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const serverId = recoverMatch[1];
      const body = await parseBody(req);
      const approvedBy = body.approvedBy || "admin";
      const success = sentinel.quarantineManager.recover(serverId, approvedBy);
      if (!success) {
        sendJson(res, 400, { error: `Server ${serverId} is not quarantined or not found` });
        return;
      }
      sendJson(res, 200, { success: true, message: `Server ${serverId} recovered to MONITOR state` });
      return;
    }

    // ── POST: Demo Trigger Malicious Mode ──
    if (
      (url.pathname === "/api/sentinel/trigger-malicious" || url.pathname === "/api/trigger-malicious") &&
      req.method === "POST"
    ) {
      if (!sentinel) {
        sendJson(res, 400, { error: "Sentinel not enabled" });
        return;
      }
      const body = await parseBody(req);
      const serverName = body.serverName || "rugpull-server";
      const active = body.active !== undefined ? Boolean(body.active) : true;
      sentinel.setServerMaliciousMode(serverName, active);
      process.env.MALICIOUS_MODE = active ? "true" : "false";

      sendJson(res, 200, {
        success: true,
        serverName,
        maliciousMode: active,
        message: active
          ? `Malicious rug-pull mode activated for ${serverName}`
          : `Malicious mode deactivated for ${serverName}`,
      });
      return;
    }

    // ── Serve HTML Dashboard ──
    res.setHeader("Content-Type", "text/html");
    res.end(htmlContent);
  });

  server.listen(opts.port, () => {
    process.stderr.write(`[mcp-sentinel] Security Dashboard running at: http://localhost:${opts.port}\n`);
  });
}
