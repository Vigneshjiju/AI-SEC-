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
import type { AuthManager } from "./auth.js";
import { classifyTool, isDestructiveToolName } from "./capability-model.js";

/** Capability classes whose invocation is always gated behind a human. */
const HIGH_RISK_CAPABILITIES = new Set(["INFRASTRUCTURE_CONTROL", "SECRET_ACCESS", "EXEC", "DATA_TRANSFER"]);

/** How long a granted approval remains redeemable before it must be re-requested. */
const APPROVAL_GRANT_TTL_MS = 300_000;

let approvalCounter = 0;

interface ApprovalGrant {
  approvalId: string;
  decidedBy: string;
  expiresAt: number;
}

export class PolicyEngine {
  private config: SentinelConfig;
  private registry: ServerRegistry;
  private authManager: AuthManager;
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();
  /**
   * Single-use redemptions for approvals that a human granted.
   *
   * Without this, approving a request changes a status field and nothing else:
   * the agent retries, hits the same rule, and opens another request forever.
   * The grant lets exactly one subsequent matching call through.
   */
  private approvalGrants: Map<string, ApprovalGrant> = new Map();

  constructor(config: SentinelConfig, registry: ServerRegistry, authManager: AuthManager) {
    this.config = config;
    this.registry = registry;
    this.authManager = authManager;
  }

  private grantKey(serverId: string, tool: string, userId: string): string {
    return `${serverId}::${tool}::${userId}`;
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

    // 2. Authorization check — capability-tiered RBAC with JIT grants
    const tool = this.registry.getTool(ctx.toolId) ?? this.registry.getToolByName(ctx.serverId, ctx.tool);
    const identity = this.authManager.identityForRole(ctx.userId, ctx.userRole);
    const authCheck = this.authManager.canExecuteTool(
      identity,
      ctx.tool,
      tool?.sensitivity ?? "internal",
      tool?.description,
    );

    if (!authCheck.allowed) {
      return {
        action: "block",
        reason: authCheck.reason ?? `Role "${ctx.userRole}" is not authorized to use tool "${ctx.tool}"`,
        evidence: [
          `Tool capability class: ${authCheck.capability}`,
          `User role: ${ctx.userRole}`,
          `No active JIT grant covers this capability`,
        ],
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

    // 3. Redeem a human approval that was already granted for this exact call.
    //    Checked before the approval-producing rules so an approved action can
    //    actually proceed instead of looping back into a new request.
    const redeemed = this.consumeApprovalGrant(ctx);
    if (redeemed) {
      return {
        action: "allow",
        reason: `Human approval ${redeemed.approvalId} granted by ${redeemed.decidedBy} — proceeding`,
        evidence: [`Approval ${redeemed.approvalId}`, `Decided by: ${redeemed.decidedBy}`, "Single-use grant consumed"],
        policy: "approval-granted",
        riskScore: ctx.riskScore,
        securityState: ctx.securityState,
        timestamp,
        isHardRule: false,
      };
    }

    // 4. State-based enforcement
    const stateDecision = this.evaluateByState(ctx, timestamp);
    if (stateDecision) return stateDecision;

    // 5. High-risk capability class → require approval
    const profile = classifyTool(ctx.tool, tool?.description);
    if (HIGH_RISK_CAPABILITIES.has(profile.primaryCapability)) {
      return {
        action: "require-approval",
        reason: `Tool "${ctx.tool}" exercises high-risk capability ${profile.primaryCapability} and requires human approval`,
        evidence: [
          `Capability class: ${profile.primaryCapability}`,
          `Risk tier: ${profile.riskTier}`,
          `Current risk score: ${ctx.riskScore}`,
        ],
        policy: "risk-high-risk-capability",
        riskScore: ctx.riskScore,
        securityState: ctx.securityState,
        timestamp,
        isHardRule: false,
      };
    }

    // 6. Destructive tool → require approval
    if (this.isDestructive(ctx.tool) || ctx.annotations?.destructiveHint) {
      return {
        action: "require-approval",
        reason: `Destructive tool "${ctx.tool}" requires human approval`,
        evidence: [
          ctx.annotations?.destructiveHint
            ? `Upstream server marked this tool destructiveHint: true`
            : `Tool "${ctx.tool}" matches destructive naming pattern`,
        ],
        policy: "risk-destructive-tool",
        riskScore: ctx.riskScore,
        securityState: ctx.securityState,
        timestamp,
        isHardRule: false,
      };
    }

    // 7. Default — allow
    return {
      action: "allow",
      reason: "Tool call permitted by policy",
      evidence: [`Capability class: ${profile.primaryCapability}`, `Authorized via: ${authCheck.via}`],
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
        if (
          this.isDestructive(ctx.tool) ||
          HIGH_RISK_CAPABILITIES.has(classifyTool(ctx.tool).primaryCapability)
        ) {
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

  private isDestructive(tool: string): boolean {
    return isDestructiveToolName(tool);
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

    // Issue the single-use grant that lets the retried call actually run.
    this.approvalGrants.set(this.grantKey(req.serverId, req.toolName, req.userId), {
      approvalId: req.id,
      decidedBy,
      expiresAt: Date.now() + APPROVAL_GRANT_TTL_MS,
    });

    return req;
  }

  /**
   * Redeems and removes a granted approval matching this call, if one exists.
   * Grants are single-use and time-limited.
   */
  consumeApprovalGrant(ctx: SentinelToolContext): ApprovalGrant | null {
    const key = this.grantKey(ctx.serverId, ctx.tool, ctx.userId);
    const grant = this.approvalGrants.get(key);
    if (!grant) return null;

    this.approvalGrants.delete(key);
    if (Date.now() > grant.expiresAt) return null;

    return grant;
  }

  /** Grants that have been approved but not yet redeemed (dashboard telemetry). */
  getOpenGrants(): Array<{ key: string; approvalId: string; decidedBy: string; expiresAt: string }> {
    const now = Date.now();
    const open: Array<{ key: string; approvalId: string; decidedBy: string; expiresAt: string }> = [];
    for (const [key, grant] of this.approvalGrants) {
      if (grant.expiresAt <= now) {
        this.approvalGrants.delete(key);
        continue;
      }
      open.push({
        key,
        approvalId: grant.approvalId,
        decidedBy: grant.decidedBy,
        expiresAt: new Date(grant.expiresAt).toISOString(),
      });
    }
    return open;
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
    const now = Date.now();
    const pending: ApprovalRequest[] = [];
    for (const req of this.pendingApprovals.values()) {
      if (req.status !== "pending") continue;
      // Expire requests that nobody acted on rather than showing them forever.
      if (new Date(req.expiresAt).getTime() <= now) {
        req.status = "expired";
        continue;
      }
      pending.push(req);
    }
    return pending;
  }

  getAllApprovals(): ApprovalRequest[] {
    return Array.from(this.pendingApprovals.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
  }

  getApproval(id: string): ApprovalRequest | undefined {
    return this.pendingApprovals.get(id);
  }

  /** Clears approvals and grants — used when resetting to a clean baseline. */
  reset(): void {
    this.pendingApprovals.clear();
    this.approvalGrants.clear();
  }
}
