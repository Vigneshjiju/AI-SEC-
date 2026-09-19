/**
 * MCP-Sentinel: Policy Engine
 * Hard rules (always enforced) + risk-based adaptive policies.
 * Distinguishes HARD POLICY from RISK-BASED DECISION.
 */

import type {
  PolicyDecision,
  SecurityState,
  SentinelConfig,
  UserIdentity,
  SentinelToolContext,
  ApprovalRequest,
} from "./types.js";
import type { ServerRegistry } from "./registry.js";

// ── Role permissions ──

const ROLE_PERMISSIONS: Record<UserIdentity["role"], Set<string>> = {
  viewer: new Set(["search_logs", "lookup_ip", "read_graph", "search_nodes"]),
  analyst: new Set(["search_logs", "lookup_ip", "create_incident", "read_graph", "search_nodes", "create_entities", "add_observations"]),
  incident_responder: new Set(["search_logs", "lookup_ip", "create_incident", "block_ip", "read_graph", "search_nodes", "create_entities", "add_observations", "delete_entities"]),
  admin: new Set(["*"]), // Admin can use all tools
};

// ── Destructive tool patterns ──

const DESTRUCTIVE_PATTERNS = [
  /^block_ip$/i,
  /^isolate_host$/i,
  /^delete/i,
  /^drop/i,
  /^remove/i,
  /^shutdown/i,
  /^kill/i,
];

const HIGH_RISK_TOOLS = new Set(["block_ip", "isolate_host", "delete_entities"]);

let approvalCounter = 0;

export class PolicyEngine {
  private config: SentinelConfig;
  private registry: ServerRegistry;
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();

  constructor(config: SentinelConfig, registry: ServerRegistry) {
    this.config = config;
    this.registry = registry;
  }

  /**
   * Evaluate a tool call against all policies.
   * Returns the policy decision with full explanation.
   */
  evaluate(ctx: SentinelToolContext): PolicyDecision {
    const timestamp = new Date().toISOString();

    // ══════════════════════════════════════
    // HARD RULES — never overridden by risk
    // ══════════════════════════════════════

    // 1. Quarantined server → BLOCK
    const server = this.registry.getServer(ctx.serverId) ?? this.registry.getServerByName(ctx.server);
    if ((server && this.registry.isQuarantined(server.serverId)) || ctx.securityState === "QUARANTINE") {
      return {
        action: "block",
        reason: `Server "${ctx.server}" is quarantined`,
        evidence: [server?.quarantineStatus?.reason ?? "Quarantine active: risk score exceeded threshold"],
        policy: "hard-quarantine",
        riskScore: ctx.riskScore,
        securityState: "QUARANTINE",
        timestamp,
        isHardRule: true,
      };
    }

    // 2. Authorization check — tool permission by role
    if (!this.hasPermission(ctx.userRole as UserIdentity["role"], ctx.tool)) {
      return {
        action: "block",
        reason: `Role "${ctx.userRole}" is not authorized to use tool "${ctx.tool}"`,
        evidence: [`Required permission: ${ctx.tool}`, `User role: ${ctx.userRole}`],
        policy: "hard-authorization",
        riskScore: ctx.riskScore,
        securityState: ctx.securityState,
        timestamp,
        isHardRule: true,
      };
    }

    // ══════════════════════════════════════
    // RISK-BASED DECISIONS — adaptive
    // ══════════════════════════════════════

    // 3. State-based enforcement
    const stateDecision = this.evaluateByState(ctx, timestamp);
    if (stateDecision) return stateDecision;

    // 4. High-risk tool + elevated risk → require approval
    if (HIGH_RISK_TOOLS.has(ctx.tool) && ctx.riskScore > 30) {
      return {
        action: "require-approval",
        reason: `High-risk tool "${ctx.tool}" requires human approval (risk: ${ctx.riskScore})`,
        evidence: [`Tool "${ctx.tool}" is classified as high-risk`, `Current risk score: ${ctx.riskScore}`],
        policy: "risk-high-risk-tool",
        riskScore: ctx.riskScore,
        securityState: ctx.securityState,
        timestamp,
        isHardRule: false,
      };
    }

    // 5. Destructive tool → require approval
    if (this.isDestructive(ctx.tool) || ctx.annotations?.destructiveHint) {
      return {
        action: "require-approval",
        reason: `Destructive tool "${ctx.tool}" requires human approval`,
        evidence: [`Tool "${ctx.tool}" matches destructive pattern`],
        policy: "risk-destructive-tool",
        riskScore: ctx.riskScore,
        securityState: ctx.securityState,
        timestamp,
        isHardRule: false,
      };
    }

    // 6. Default — allow
    return {
      action: "allow",
      reason: "Tool call permitted by policy",
      evidence: [],
      policy: "default-allow",
      riskScore: ctx.riskScore,
      securityState: ctx.securityState,
      timestamp,
      isHardRule: false,
    };
  }

  private evaluateByState(ctx: SentinelToolContext, timestamp: string): PolicyDecision | null {
    switch (ctx.securityState) {
      case "QUARANTINE":
        return {
          action: "block",
          reason: `Security state is QUARANTINE — all tool calls blocked`,
          evidence: [`Risk score: ${ctx.riskScore}`, `State: QUARANTINE`],
          policy: "state-quarantine",
          riskScore: ctx.riskScore,
          securityState: ctx.securityState,
          timestamp,
          isHardRule: false,
        };

      case "HUMAN_APPROVAL":
        return {
          action: "require-approval",
          reason: `Security state is HUMAN_APPROVAL — tool "${ctx.tool}" requires explicit approval`,
          evidence: [`Risk score: ${ctx.riskScore}`, `State: HUMAN_APPROVAL`],
          policy: "state-human-approval",
          riskScore: ctx.riskScore,
          securityState: ctx.securityState,
          timestamp,
          isHardRule: false,
        };

      case "RESTRICT":
        // Allow read-only, block destructive in RESTRICT
        if (this.isDestructive(ctx.tool) || HIGH_RISK_TOOLS.has(ctx.tool)) {
          return {
            action: "block",
            reason: `Destructive tool "${ctx.tool}" blocked in RESTRICT state`,
            evidence: [`Risk score: ${ctx.riskScore}`, `State: RESTRICT`, `Tool is destructive or high-risk`],
            policy: "state-restrict",
            riskScore: ctx.riskScore,
            securityState: ctx.securityState,
            timestamp,
            isHardRule: false,
          };
        }
        if (!ctx.annotations?.readOnlyHint && ctx.riskScore > 60) {
          return {
            action: "require-approval",
            reason: `Non-read-only tool "${ctx.tool}" requires approval in RESTRICT state with elevated risk`,
            evidence: [`Risk score: ${ctx.riskScore}`, `State: RESTRICT`],
            policy: "state-restrict-approval",
            riskScore: ctx.riskScore,
            securityState: ctx.securityState,
            timestamp,
            isHardRule: false,
          };
        }
        return null; // Allow read-only in RESTRICT

      case "MONITOR":
        // MONITOR: allow everything, but flag high-risk
        return null;

      case "NORMAL":
      default:
        return null;
    }
  }

  private hasPermission(role: UserIdentity["role"], tool: string): boolean {
    const perms = ROLE_PERMISSIONS[role];
    if (!perms) return false;
    if (perms.has("*")) return true;
    return perms.has(tool);
  }

  private isDestructive(tool: string): boolean {
    return DESTRUCTIVE_PATTERNS.some(p => p.test(tool));
  }

  // ── Approval Management ──

  createApprovalRequest(ctx: SentinelToolContext, reason: string, reasons: string[]): ApprovalRequest {
    const id = `approval_${Date.now().toString(36)}_${(++approvalCounter).toString(36)}`;
    const request: ApprovalRequest = {
      id,
      serverId: ctx.serverId,
      toolId: ctx.toolId,
      toolName: ctx.tool,
      userId: ctx.userId,
      userRole: ctx.userRole,
      action: "tool_call",
      args: ctx.args,
      riskScore: ctx.riskScore,
      reasons,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 300_000).toISOString(), // 5 min
      status: "pending",
    };
    this.pendingApprovals.set(id, request);
    return request;
  }

  approveRequest(id: string, decidedBy: string): ApprovalRequest | null {
    const req = this.pendingApprovals.get(id);
    if (!req || req.status !== "pending") return null;
    req.status = "approved";
    req.decidedBy = decidedBy;
    req.decidedAt = new Date().toISOString();
    return req;
  }

  denyRequest(id: string, decidedBy: string): ApprovalRequest | null {
    const req = this.pendingApprovals.get(id);
    if (!req || req.status !== "pending") return null;
    req.status = "denied";
    req.decidedBy = decidedBy;
    req.decidedAt = new Date().toISOString();
    return req;
  }

  getPendingApprovals(): ApprovalRequest[] {
    return Array.from(this.pendingApprovals.values()).filter(r => r.status === "pending");
  }

  getApproval(id: string): ApprovalRequest | undefined {
    return this.pendingApprovals.get(id);
  }
}
