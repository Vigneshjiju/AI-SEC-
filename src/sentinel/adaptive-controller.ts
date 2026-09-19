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
import { IdentityVerifier } from "./identity.js";
import { SemanticChangeFirewall } from "./semantic-firewall.js";
import { CapabilityLeaseManager } from "./lease-manager.js";
import { ContextualSecurityEngine } from "./contextual-engine.js";
import { DataFlowGuard } from "./data-flow.js";
import { InputValidator } from "./input-validator.js";
import { OutputValidator } from "./output-scanner.js";
import { ThreatDetector } from "./threat-detector.js";
import { DecisionReceiptsLedger } from "./receipts.js";

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
  readonly outputValidator: OutputValidator;
  readonly eventBus: SentinelEventBus;
  readonly authManager: AuthManager;
  readonly identityVerifier: IdentityVerifier;
  readonly semanticFirewall: SemanticChangeFirewall;
  readonly leaseManager: CapabilityLeaseManager;
  readonly contextualEngine: ContextualSecurityEngine;
  readonly dataFlowGuard: DataFlowGuard;
  readonly inputValidator: InputValidator;
  readonly threatDetector: ThreatDetector;
  readonly receiptsLedger: DecisionReceiptsLedger;

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
    this.outputValidator = new OutputValidator();
    this.authManager = new AuthManager(this.config.auth.mode, this.config.auth.defaultRole);
    this.identityVerifier = new IdentityVerifier();
    this.semanticFirewall = new SemanticChangeFirewall();
    this.leaseManager = new CapabilityLeaseManager(this.eventBus);
    this.contextualEngine = new ContextualSecurityEngine();
    this.dataFlowGuard = new DataFlowGuard();
    this.inputValidator = new InputValidator();
    this.threatDetector = new ThreatDetector();
    this.receiptsLedger = new DecisionReceiptsLedger();
  }

  /**
   * PRE-EXECUTION: Evaluate whether a tool call should proceed.
   * Called BEFORE the actual tool execution.
   */
  preExecute(ctx: SentinelToolContext): SentinelDecision {
    const server = this.registry.getServer(ctx.serverId) ?? this.registry.getServerByName(ctx.server);
    const serverId = server?.serverId ?? ctx.serverId;
    const tool = (ctx.toolId ? this.registry.getTool(ctx.toolId) : undefined)
      ?? this.registry.getToolByName(serverId, ctx.tool)
      ?? this.registry.getToolByPrefixedName(`${ctx.server}__${ctx.tool}`);
    const toolId = tool?.toolId ?? ctx.toolId;

    // ── 1. Identity Verifier (Never trust unverified roles) ──
    let verifiedRole = ctx.userRole;
    if (ctx.authToken) {
      const idResult = this.identityVerifier.enforceVerifiedRole(ctx.authToken, ctx.userRole, ctx.userId);
      if (!idResult.verified) {
        return this.createBlockDecision(
          ctx,
          `Identity verification failed: ${idResult.reason}`,
          "identity-verifier",
          serverId,
          toolId,
          90
        );
      }
      verifiedRole = idResult.primaryRole;
    }

    // ── 2. Check quarantine (hard rule) ──
    if (ctx.securityState === "QUARANTINE" || (server && this.quarantineManager.isQuarantined(serverId))) {
      const riskScore = server?.currentRisk ?? ctx.riskScore ?? 100;
      return this.createBlockDecision(
        ctx,
        `Server "${ctx.server}" is quarantined`,
        "hard-quarantine",
        serverId,
        toolId,
        riskScore
      );
    }

    // ── 3. Input Validation (SSRF, Traversal, Command Injection) ──
    const inputValidation = this.inputValidator.validate(ctx.tool, ctx.args);
    if (!inputValidation.valid) {
      const reason = inputValidation.violations.map((v) => v.message).join("; ");
      return this.createBlockDecision(
        ctx,
        `Hostile input rejected: ${reason}`,
        "input-validator",
        serverId,
        toolId,
        85
      );
    }

    // ── 4. Capability Lease Validation ──
    if (ctx.leaseId) {
      const toolProf = this.contextualEngine.getToolProfile(ctx.tool);
      const leaseValidation = this.leaseManager.validateLease({
        leaseId: ctx.leaseId,
        toolId,
        capability: toolProf.primaryCapability,
        workflowId: ctx.workflowId,
      });
      if (!leaseValidation.valid) {
        return this.createBlockDecision(
          ctx,
          `Capability lease rejected: ${leaseValidation.reason}`,
          "lease-manager",
          serverId,
          toolId,
          75
        );
      }
    }

    // ── 5. Contextual Tool-Call Engine & Capability Transition Analysis ──
    if (ctx.workflowId) {
      const contextualResult = this.contextualEngine.evaluateToolCall({
        workflowId: ctx.workflowId,
        userId: ctx.userId,
        agentId: ctx.agentId,
        intent: ctx.intent,
        server: ctx.server,
        tool: ctx.tool,
        toolId,
        args: ctx.args,
      });

      if (contextualResult.action === "block") {
        return this.createBlockDecision(
          ctx,
          contextualResult.reason,
          "contextual-engine",
          serverId,
          toolId,
          Math.max(server?.currentRisk ?? 0, 80),
          contextualResult
        );
      }
    }

    // ── 6. Data-Flow Guard ──
    if (ctx.workflowId) {
      const toolProf = this.contextualEngine.getToolProfile(ctx.tool);
      const dataFlowResult = this.dataFlowGuard.checkDataFlow({
        workflowId: ctx.workflowId,
        toolName: ctx.tool,
        capability: toolProf.primaryCapability,
        args: ctx.args,
      });

      if (!dataFlowResult.allowed && dataFlowResult.violation) {
        return this.createBlockDecision(
          ctx,
          dataFlowResult.violation.reason,
          "data-flow-guard",
          serverId,
          toolId,
          85
        );
      }
    }

    // ── 7. Get current state & apply policy engine ──
    const currentState = server ? this.stateMachine.getState(serverId) : "NORMAL";
    const currentRisk = server?.currentRisk ?? 0;

    const enrichedCtx: SentinelToolContext = {
      ...ctx,
      userRole: verifiedRole,
      serverId,
      riskScore: currentRisk,
      securityState: currentState,
    };

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

  private createBlockDecision(
    ctx: SentinelToolContext,
    reason: string,
    policyName: string,
    serverId: string,
    toolId: string,
    riskScore: number,
    contextualResult?: import("./contextual-engine.js").ContextualEvaluationResult
  ): SentinelDecision {
    const decision: PolicyDecision = {
      action: "block",
      reason,
      evidence: [reason],
      policy: policyName,
      riskScore,
      securityState: ctx.securityState === "QUARANTINE" ? "QUARANTINE" : "RESTRICT",
      timestamp: new Date().toISOString(),
      isHardRule: true,
    };
    this.emitToolEvent("TOOL_BLOCKED", ctx, riskScore, decision);

    if (ctx.workflowId) {
      const toolProf = this.contextualEngine.getToolProfile(ctx.tool);
      this.receiptsLedger.recordReceiptSync({
        workflowId: ctx.workflowId,
        tool: ctx.tool,
        toolId,
        server: ctx.server,
        decision: "BLOCK",
        riskScore,
        state: decision.securityState,
        reasons: [reason],
        evidence: contextualResult?.isDangerousSequence
          ? [JSON.stringify(contextualResult.capabilityTransition)]
          : [reason],
        previousTools: contextualResult?.workflowContext
          ? contextualResult.workflowContext.toolCallHistory.map((t) => t.toolName)
          : [],
        capabilityTransitions: contextualResult?.capabilityTransition
          ? [{ from: contextualResult.capabilityTransition.fromCapability, to: contextualResult.capabilityTransition.toCapability }]
          : [{ to: toolProf.primaryCapability }],
        activeLeaseId: ctx.leaseId,
      });
    }

    return {
      action: "block",
      reason,
      policyDecision: decision,
      riskAssessment: null,
      driftFindings: [],
      securityState: decision.securityState,
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

    // ── Unconditional Quarantine Check on critical score ──
    if (riskAssessment.score >= this.config.risk.thresholds.quarantine && !this.quarantineManager.isQuarantined(serverId)) {
      this.quarantineManager.quarantine(
        serverId,
        `Risk score ${riskAssessment.score} exceeded quarantine threshold`,
        riskAssessment.score,
        riskAssessment.reasons,
        "adaptive-controller",
      );
      quarantined = true;
    }

    // ── Capability Lease Auto-Revocation on Critical Risk ──
    if (quarantined || riskAssessment.score >= this.config.risk.thresholds.quarantine) {
      this.leaseManager.onRiskEscalation(toolId, ctx.workflowId, riskAssessment.score);
    }

    // ── Data-Flow Guard Taint Recording ──
    if (ctx.workflowId) {
      this.dataFlowGuard.recordTaint({
        workflowId: ctx.workflowId,
        originTool: ctx.tool,
        originResource: server?.serverName ?? ctx.server,
        outputText,
      });
    }

    // ── Contextual Tool-Call Engine Record ──
    if (ctx.workflowId) {
      this.contextualEngine.recordCall(
        ctx.workflowId,
        toolId,
        ctx.tool,
        ctx.server,
        ctx.args,
        quarantined ? "block" : "allow",
        riskAssessment.score
      );
    }

    // ── Multi-Signal Threat Detection ──
    this.threatDetector.correlateThreats({
      identityVerified: true,
      driftFindings,
      outputFindings,
      descriptorChanged: evidence.descriptorChanged,
    });

    // ── Verifiable Decision Receipt Record ──
    if (ctx.workflowId) {
      const toolProf = this.contextualEngine.getToolProfile(ctx.tool);
      this.receiptsLedger.recordReceiptSync({
        workflowId: ctx.workflowId,
        tool: ctx.tool,
        toolId,
        server: ctx.server,
        decision: quarantined ? "QUARANTINE" : (riskAssessment.state === "RESTRICT" ? "RESTRICT" : "ALLOW"),
        riskScore: riskAssessment.score,
        state: riskAssessment.state,
        reasons: riskAssessment.reasons.length > 0 ? riskAssessment.reasons : ["Tool executed within normal baseline"],
        evidence: driftFindings.map((f) => f.message),
        previousTools: (this.contextualEngine.getOrCreateWorkflowContext(ctx.workflowId, ctx.userId).toolCallHistory || []).map((t) => t.toolName),
        capabilityTransitions: [{ to: toolProf.primaryCapability }],
        activeLeaseId: ctx.leaseId,
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

  getIdentityVerifier(): IdentityVerifier { return this.identityVerifier; }
  getSemanticFirewall(): SemanticChangeFirewall { return this.semanticFirewall; }
  getLeaseManager(): CapabilityLeaseManager { return this.leaseManager; }
  getContextualEngine(): ContextualSecurityEngine { return this.contextualEngine; }
  getDataFlowGuard(): DataFlowGuard { return this.dataFlowGuard; }
  getInputValidator(): InputValidator { return this.inputValidator; }
  getOutputValidator(): OutputValidator { return this.outputValidator; }
  getThreatDetector(): ThreatDetector { return this.threatDetector; }
  getReceiptsLedger(): DecisionReceiptsLedger { return this.receiptsLedger; }
  getQuarantineManager(): QuarantineManager { return this.quarantineManager; }
}

