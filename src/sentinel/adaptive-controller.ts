/**
 * MCP-Sentinel: Adaptive Controller
 * Central orchestrator — connects all Sentinel modules.
 * Implements the core security loop:
 *   Validate → Observe → Assess Risk → Apply Policy → Control → Observe Again ↺
 */

import type {
  SentinelConfig,
  SentinelToolContext,
  SecurityState,
  PolicyDecision,
  RiskAssessment,
  BehaviorFingerprint,
  BehaviorDriftFinding,
  SecurityEvent,
  ApprovalRequest,
  QuarantineRecord,
  UserIdentity,
} from "./types.js";
import { defaultSentinelConfig, createEmptyFingerprint, createEmptyCapabilitySet } from "./types.js";
import { ServerRegistry } from "./registry.js";
import { BehaviorEngine } from "./behavior.js";
import { RiskEngine, type RiskEvidence } from "./risk-engine.js";
import { SecurityStateMachine } from "./state-machine.js";
import { PolicyEngine } from "./policy.js";
import { RuntimeGuard } from "./runtime.js";
import { QuarantineManager } from "./quarantine.js";
import { OutputScanner } from "./output-scanner.js";
import { SentinelEventBus } from "./events.js";
import { AuthManager } from "./auth.js";

export interface SentinelDecision {
  action: "allow" | "block" | "require-approval";
  reason: string;
  policyDecision: PolicyDecision;
  riskAssessment: RiskAssessment | null;
  driftFindings: BehaviorDriftFinding[];
  securityState: SecurityState;
  approvalRequest?: ApprovalRequest;
}

export class AdaptiveController {
  readonly config: SentinelConfig;
  readonly registry: ServerRegistry;
  readonly behaviorEngine: BehaviorEngine;
  readonly riskEngine: RiskEngine;
  readonly stateMachine: SecurityStateMachine;
  readonly policyEngine: PolicyEngine;
  readonly runtimeGuard: RuntimeGuard;
  readonly quarantineManager: QuarantineManager;
  readonly outputScanner: OutputScanner;
  readonly eventBus: SentinelEventBus;
  readonly authManager: AuthManager;

  private maliciousModeServers: Set<string> = new Set();

  constructor(config?: Partial<SentinelConfig>) {
    this.config = { ...defaultSentinelConfig(), ...config };
    this.registry = new ServerRegistry();
    this.behaviorEngine = new BehaviorEngine(this.config);
    this.riskEngine = new RiskEngine(this.config);
    this.stateMachine = new SecurityStateMachine(this.config);
    this.eventBus = new SentinelEventBus();
    this.policyEngine = new PolicyEngine(this.config, this.registry);
    this.runtimeGuard = new RuntimeGuard(this.config);
    this.quarantineManager = new QuarantineManager(this.registry, this.stateMachine, this.eventBus);
    this.outputScanner = new OutputScanner();
    this.authManager = new AuthManager(this.config.auth.mode, this.config.auth.defaultRole);
  }

  /**
   * PRE-EXECUTION: Evaluate whether a tool call should proceed.
   * Called BEFORE the actual tool execution.
   */
  preExecute(ctx: SentinelToolContext): SentinelDecision {
    const server = this.registry.getServer(ctx.serverId) ?? this.registry.getServerByName(ctx.server);
    const serverId = server?.serverId ?? ctx.serverId;

    // ── Check quarantine (hard rule) ──
    if (ctx.securityState === "QUARANTINE" || (server && this.quarantineManager.isQuarantined(serverId))) {
      const riskScore = server?.currentRisk ?? ctx.riskScore ?? 100;
      const decision: PolicyDecision = {
        action: "block",
        reason: `Server "${ctx.server}" is quarantined`,
        evidence: [server?.quarantineStatus?.reason ?? "Server quarantined"],
        policy: "hard-quarantine",
        riskScore,
        securityState: "QUARANTINE",
        timestamp: new Date().toISOString(),
        isHardRule: true,
      };
      this.emitToolEvent("TOOL_BLOCKED", ctx, riskScore, decision);
      return {
        action: "block",
        reason: decision.reason,
        policyDecision: decision,
        riskAssessment: null,
        driftFindings: [],
        securityState: "QUARANTINE",
      };
    }

    // ── Get current state ──
    const currentState = server ? this.stateMachine.getState(serverId) : "NORMAL";
    const currentRisk = server?.currentRisk ?? 0;

    // ── Build enriched context ──
    const enrichedCtx: SentinelToolContext = {
      ...ctx,
      serverId,
      riskScore: currentRisk,
      securityState: currentState,
    };

    // ── Apply policy ──
    const policyDecision = this.policyEngine.evaluate(enrichedCtx);

    if (policyDecision.action === "block") {
      this.emitToolEvent("TOOL_BLOCKED", enrichedCtx, currentRisk, policyDecision);
      return {
        action: "block",
        reason: policyDecision.reason,
        policyDecision,
        riskAssessment: null,
        driftFindings: [],
        securityState: currentState,
      };
    }

    if (policyDecision.action === "require-approval") {
      const approvalRequest = this.policyEngine.createApprovalRequest(
        enrichedCtx, policyDecision.reason, policyDecision.evidence
      );
      this.emitToolEvent("APPROVAL_REQUIRED", enrichedCtx, currentRisk, policyDecision);
      return {
        action: "require-approval",
        reason: policyDecision.reason,
        policyDecision,
        riskAssessment: null,
        driftFindings: [],
        securityState: currentState,
        approvalRequest,
      };
    }

    if (policyDecision.action === "quarantine") {
      this.quarantineManager.quarantine(serverId, policyDecision.reason, currentRisk, policyDecision.evidence, "policy-engine");
      return {
        action: "block",
        reason: policyDecision.reason,
        policyDecision,
        riskAssessment: null,
        driftFindings: [],
        securityState: "QUARANTINE",
      };
    }

    // ── Allow ──
    this.emitToolEvent("TOOL_ALLOWED", enrichedCtx, currentRisk, policyDecision);
    return {
      action: "allow",
      reason: policyDecision.reason,
      policyDecision,
      riskAssessment: null,
      driftFindings: [],
      securityState: currentState,
    };
  }

  /**
   * POST-EXECUTION: Analyze tool output and update risk.
   * Called AFTER the tool returns results.
   * This is where rug-pull detection happens.
   */
  postExecute(
    ctx: SentinelToolContext,
    outputText: string,
    responseTimeMs: number,
  ): {
    riskAssessment: RiskAssessment;
    driftFindings: BehaviorDriftFinding[];
    stateTransition: { from: SecurityState; to: SecurityState } | null;
    quarantined: boolean;
  } {
    const server = this.registry.getServer(ctx.serverId) ?? this.registry.getServerByName(ctx.server);
    const serverId = server?.serverId ?? ctx.serverId;
    const tool = (ctx.toolId ? this.registry.getTool(ctx.toolId) : undefined)
      ?? this.registry.getToolByName(serverId, ctx.tool)
      ?? this.registry.getToolByPrefixedName(`${ctx.server}__${ctx.tool}`);
    const toolId = tool?.toolId ?? ctx.toolId;

    // ── Record the call ──
    if (tool) this.registry.recordToolCall(toolId);

    // ── Analyze output for behavioral fingerprint ──
    const observed = this.behaviorEngine.analyzeOutput(toolId, outputText, responseTimeMs);

    // ── Compare against baseline ──
    let driftFindings: BehaviorDriftFinding[] = [];
    const baseline = tool?.baselineFingerprint;

    if (baseline) {
      driftFindings = this.behaviorEngine.compareFingerprint(
        baseline,
        observed,
        tool?.declaredCapabilities ?? createEmptyCapabilitySet(),
        tool?.authorizedCapabilities ?? createEmptyCapabilitySet(),
      );
    } else {
      // No baseline — this IS the baseline
      if (tool) {
        this.registry.setBaseline(toolId, observed);
        this.emitEvent("BASELINE_CREATED", serverId, server?.serverName ?? ctx.server, 0, [], toolId, ctx.tool);
      }
    }

    // ── Runtime guard ──
    const runtimeEvents = this.runtimeGuard.inspectOutput(
      outputText,
      tool?.authorizedCapabilities ?? createEmptyCapabilitySet(),
    );

    // ── Output scanner ──
    const outputFindings = this.outputScanner.scan(outputText);

    // ── Build risk evidence ──
    const evidence: RiskEvidence = {
      toolId,
      serverId,
      driftFindings: driftFindings.length > 0 ? driftFindings : undefined,
      descriptorChanged: false,
      runtimeViolations: runtimeEvents
        .filter(e => !e.allowed)
        .map(e => ({ severity: "high" as const, message: e.detail })),
      sensitiveFileAccess: observed.sensitiveFileAccess,
      sensitiveDataAccess: observed.envAccess,
      capabilityMismatch: driftFindings.some(f => f.type === "CAPABILITY_MISMATCH"),
      outputAnomaly: outputFindings.length > 0,
      previousIncidents: server?.incidentCount ?? 0,
    };

    // ── Assess risk ──
    const riskAssessment = this.riskEngine.assess(serverId, evidence);

    // ── Update fingerprint ──
    if (tool) {
      this.registry.updateFingerprint(toolId, observed);
      this.registry.updateToolRisk(toolId, riskAssessment.score);
    }

    // ── Update server risk ──
    this.registry.updateServerRisk(serverId, riskAssessment.score, riskAssessment.state);

    // ── Evaluate state transition ──
    const { currentState, newState, transition } = this.stateMachine.evaluate(serverId, riskAssessment.score);
    let stateTransition: { from: SecurityState; to: SecurityState } | null = null;
    let quarantined = false;

    if (transition) {
      stateTransition = { from: transition.from, to: transition.to };

      // Emit state transition event
      this.eventBus.emit({
        id: `evt_${Date.now().toString(36)}`,
        type: "STATE_TRANSITION",
        timestamp: new Date().toISOString(),
        serverId,
        serverName: server?.serverName ?? ctx.server,
        toolId,
        toolName: ctx.tool,
        riskScore: riskAssessment.score,
        riskDelta: riskAssessment.delta,
        securityState: transition.to,
        previousState: transition.from,
        decision: transition.to,
        reasons: riskAssessment.reasons,
        evidence: driftFindings.map(f => f.message),
        policy: "state-machine",
      });

      // ── Auto-quarantine if threshold reached ──
      if (transition.to === "QUARANTINE") {
        this.quarantineManager.quarantine(
          serverId,
          `Risk score ${riskAssessment.score} exceeded quarantine threshold`,
          riskAssessment.score,
          riskAssessment.reasons,
          "adaptive-controller",
        );
        quarantined = true;
      }

      // Update trust status based on state
      if (server) {
        if (transition.to === "QUARANTINE") {
          this.registry.updateServerTrust(serverId, "QUARANTINED");
        } else if (transition.to === "RESTRICT" || transition.to === "HUMAN_APPROVAL") {
          this.registry.updateServerTrust(serverId, "SUSPICIOUS");
        } else if (transition.to === "MONITOR") {
          this.registry.updateServerTrust(serverId, "PROVISIONAL");
        }
      }

      process.stderr.write(
        `[sentinel] State transition: ${transition.from} → ${transition.to} ` +
        `(server: ${server?.serverName ?? ctx.server}, risk: ${riskAssessment.score})\n`
      );
    }

    // ── Emit drift event if detected ──
    if (driftFindings.length > 0) {
      this.eventBus.emit({
        id: `evt_${Date.now().toString(36)}`,
        type: "BEHAVIOR_DRIFT",
        timestamp: new Date().toISOString(),
        serverId,
        serverName: server?.serverName ?? ctx.server,
        toolId,
        toolName: ctx.tool,
        riskScore: riskAssessment.score,
        riskDelta: riskAssessment.delta,
        securityState: newState,
        reasons: driftFindings.map(f => f.message),
        evidence: driftFindings.map(f => f.evidence),
        driftFindings,
        policy: "behavior-engine",
      });

      process.stderr.write(
        `[sentinel] ⚠️  Behavioral drift detected for ${ctx.server}/${ctx.tool}: ` +
        `${driftFindings.length} finding(s), risk: ${riskAssessment.score}\n`
      );
    }

    // ── Emit risk change event ──
    if (riskAssessment.delta !== 0) {
      this.eventBus.emit({
        id: `evt_${Date.now().toString(36)}`,
        type: "RISK_CHANGE",
        timestamp: new Date().toISOString(),
        serverId,
        serverName: server?.serverName ?? ctx.server,
        toolId,
        toolName: ctx.tool,
        riskScore: riskAssessment.score,
        riskDelta: riskAssessment.delta,
        securityState: newState,
        reasons: riskAssessment.reasons,
        evidence: [],
        policy: "risk-engine",
      });
    }

    return {
      riskAssessment,
      driftFindings,
      stateTransition,
      quarantined,
    };
  }

  // ── Demo helpers ──

  /**
   * Trigger malicious mode for a server (demo only).
   */
  triggerMalicious(serverName: string): void {
    this.maliciousModeServers.add(serverName);
    process.stderr.write(`[sentinel] ⚡ Malicious mode activated for server: ${serverName}\n`);
  }

  isMaliciousMode(serverName: string): boolean {
    return this.maliciousModeServers.has(serverName);
  }

  // ── Approval management ──

  approveRequest(id: string, decidedBy: string): ApprovalRequest | null {
    const result = this.policyEngine.approveRequest(id, decidedBy);
    if (result) {
      this.eventBus.emit({
        id: `evt_${Date.now().toString(36)}`,
        type: "APPROVAL_GRANTED",
        timestamp: new Date().toISOString(),
        serverId: result.serverId,
        serverName: "",
        toolId: result.toolId,
        toolName: result.toolName,
        userId: decidedBy,
        riskScore: result.riskScore,
        riskDelta: 0,
        securityState: "NORMAL",
        reasons: [`Approved by ${decidedBy}`],
        evidence: [],
        policy: "approval-manager",
      });
    }
    return result;
  }

  denyRequest(id: string, decidedBy: string): ApprovalRequest | null {
    const result = this.policyEngine.denyRequest(id, decidedBy);
    if (result) {
      this.eventBus.emit({
        id: `evt_${Date.now().toString(36)}`,
        type: "APPROVAL_DENIED",
        timestamp: new Date().toISOString(),
        serverId: result.serverId,
        serverName: "",
        toolId: result.toolId,
        toolName: result.toolName,
        userId: decidedBy,
        riskScore: result.riskScore,
        riskDelta: 0,
        securityState: "NORMAL",
        reasons: [`Denied by ${decidedBy}`],
        evidence: [],
        policy: "approval-manager",
      });
    }
    return result;
  }

  recoverServer(serverId: string, approvedBy: string): boolean {
    return this.quarantineManager.recover(serverId, approvedBy);
  }

  // ── Status ──

  getSystemState(): {
    servers: Array<{
      serverId: string;
      serverName: string;
      trustStatus: string;
      riskScore: number;
      securityState: SecurityState;
      quarantined: boolean;
      toolCount: number;
      incidentCount: number;
    }>;
    tools: Array<{
      toolId: string;
      toolName: string;
      serverName: string;
      riskScore: number;
      state: string;
      callCount: number;
      hasDrift: boolean;
      declaredCapabilities: string[];
      observedCapabilities: string[];
    }>;
    events: SecurityEvent[];
    pendingApprovals: ApprovalRequest[];
    riskTimeline: Array<{ timestamp: string; entityId: string; score: number; state: SecurityState }>;
    quarantines: QuarantineRecord[];
    stateTransitions: Array<{ from: SecurityState; to: SecurityState; reason: string; riskScore: number; timestamp: string }>;
  } {
    const servers = this.registry.getAllServers().map(s => ({
      serverId: s.serverId,
      serverName: s.serverName,
      trustStatus: s.trustStatus,
      riskScore: s.currentRisk,
      securityState: s.securityState,
      quarantined: this.registry.isQuarantined(s.serverId),
      toolCount: s.toolIds.length,
      incidentCount: s.incidentCount,
    }));

    const tools = this.registry.getAllTools().map(t => {
      const server = this.registry.getServer(t.serverId);
      const hasDrift = t.currentFingerprint && t.baselineFingerprint
        ? this.behaviorEngine.compareFingerprint(
            t.baselineFingerprint,
            t.currentFingerprint,
            t.declaredCapabilities,
            t.authorizedCapabilities,
          ).length > 0
        : false;

      return {
        toolId: t.toolId,
        toolName: t.toolName,
        serverName: server?.serverName ?? "unknown",
        riskScore: t.riskScore,
        state: t.state,
        callCount: t.callCount,
        hasDrift,
        declaredCapabilities: this.capabilitySetToList(t.declaredCapabilities),
        observedCapabilities: t.currentFingerprint ? this.fingerprintToCapabilities(t.currentFingerprint) : [],
      };
    });

    return {
      servers,
      tools,
      events: this.eventBus.getEvents(200),
      pendingApprovals: this.policyEngine.getPendingApprovals(),
      riskTimeline: this.riskEngine.getTimeline(200),
      quarantines: this.quarantineManager.getHistory(),
      stateTransitions: this.stateMachine.getTransitions(100),
    };
  }

  private capabilitySetToList(caps: import("./types.js").CapabilitySet): string[] {
    const list: string[] = [];
    if (caps.filesystem.length > 0) list.push(`filesystem: ${caps.filesystem.join(", ")}`);
    if (caps.network.length > 0) list.push(`network: ${caps.network.join(", ")}`);
    if (caps.processes.length > 0) list.push(`processes: ${caps.processes.join(", ")}`);
    if (caps.envAccess) list.push("env_access");
    if (caps.externalNetwork) list.push("external_network");
    if (caps.sensitiveFileAccess) list.push("sensitive_file_access");
    if (caps.commandExecution) list.push("command_execution");
    return list;
  }

  private fingerprintToCapabilities(fp: BehaviorFingerprint): string[] {
    const list: string[] = [];
    if (fp.filesystem.length > 0) list.push(`filesystem: ${fp.filesystem.join(", ")}`);
    if (fp.network.length > 0) list.push(`network: ${fp.network.join(", ")}`);
    if (fp.processes.length > 0) list.push(`processes: ${fp.processes.join(", ")}`);
    if (fp.envAccess) list.push("env_access");
    if (fp.externalNetwork) list.push("external_network");
    if (fp.sensitiveFileAccess) list.push("sensitive_file_access");
    if (fp.commandExecution) list.push("command_execution");
    return list;
  }

  private emitToolEvent(
    type: SecurityEvent["type"],
    ctx: SentinelToolContext,
    riskScore: number,
    decision: PolicyDecision,
  ): void {
    this.eventBus.emit({
      id: `evt_${Date.now().toString(36)}`,
      type,
      timestamp: new Date().toISOString(),
      serverId: ctx.serverId,
      serverName: ctx.server,
      toolId: ctx.toolId,
      toolName: ctx.tool,
      userId: ctx.userId,
      riskScore,
      riskDelta: 0,
      securityState: ctx.securityState,
      decision: decision.action,
      reasons: decision.evidence,
      evidence: [],
      policy: decision.policy,
    });
  }

  private emitEvent(
    type: SecurityEvent["type"],
    serverId: string,
    serverName: string,
    riskScore: number,
    reasons: string[],
    toolId?: string,
    toolName?: string,
  ): void {
    this.eventBus.emit({
      id: `evt_${Date.now().toString(36)}`,
      type,
      timestamp: new Date().toISOString(),
      serverId,
      serverName,
      toolId,
      toolName,
      riskScore,
      riskDelta: 0,
      securityState: "NORMAL",
      reasons,
      evidence: [],
    });
  }

  getSystemOverview() {
    const servers = this.registry.getAllServers();
    const tools = this.registry.getAllTools();
    const quarantinedCount = servers.filter(
      (s) => s.trustStatus === "QUARANTINED" || s.securityState === "QUARANTINE"
    ).length;
    const maxRisk = servers.reduce((max, s) => Math.max(max, s.currentRisk), 0);
    const totalIncidents = servers.reduce((acc, s) => acc + s.incidentCount, 0);

    const statePriority: Record<SecurityState, number> = {
      QUARANTINE: 5,
      HUMAN_APPROVAL: 4,
      RESTRICT: 3,
      MONITOR: 2,
      NORMAL: 1,
    };
    let worstState: SecurityState = "NORMAL";
    for (const s of servers) {
      if (statePriority[s.securityState] > statePriority[worstState]) {
        worstState = s.securityState;
      }
    }

    const events = this.eventBus.getEvents(1000);
    const blockedCallsCount = events.filter((e) => e.decision === "block").length;

    return {
      overallState: worstState,
      maxRiskScore: maxRisk,
      activeIncidents: totalIncidents,
      quarantinedServers: quarantinedCount,
      totalServers: servers.length,
      totalTools: tools.length,
      blockedCalls: blockedCallsCount,
      timestamp: new Date().toISOString(),
    };
  }

  setServerMaliciousMode(serverName: string, active: boolean): void {
    if (active) {
      this.maliciousModeServers.add(serverName);
    } else {
      this.maliciousModeServers.delete(serverName);
    }
  }

  isServerMaliciousMode(serverName: string): boolean {
    return this.maliciousModeServers.has(serverName);
  }
}
