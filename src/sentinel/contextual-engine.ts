/**
 * MCP-Sentinel: Contextual Tool-Call Security Engine & Capability Transition Analysis
 * 
 * Evaluates whether an incoming tool call is reasonable in the context of:
 * 1. The declared user intent
 * 2. The history of prior tool calls and capabilities executed in this workflow
 * 3. The capability transition graph (detecting recon -> credential theft -> exfiltration)
 * 4. Sensitivity of resources already accessed
 * 
 * Answers: "Is this action reasonable given what the agent has already done?"
 */

import {
  WorkflowExecutionContext,
  CapabilityType,
  ToolCapabilityProfile,
  CapabilityTransitionResult,
  ToolCallRecord,
  DataClassification,
} from "./types.js";
import { classifyTool, stripServerPrefix } from "./capability-model.js";

export interface ContextualEvaluationResult {
  action: "allow" | "restrict" | "block" | "require-approval";
  reason: string;
  isDangerousSequence: boolean;
  intentAligned: boolean;
  capabilityTransition: CapabilityTransitionResult;
  riskIncrement: number;
  workflowContext: WorkflowExecutionContext;
}

export class ContextualSecurityEngine {
  private workflows: Map<string, WorkflowExecutionContext> = new Map();
  private customProfiles: Map<string, ToolCapabilityProfile> = new Map();

  /**
   * Registers or overrides a tool's capability profile.
   */
  registerToolProfile(profile: ToolCapabilityProfile): void {
    this.customProfiles.set(profile.toolName.toLowerCase(), profile);
  }

  /**
   * Returns a workflow's execution context by its ID.
   */
  getWorkflow(workflowId: string): WorkflowExecutionContext | undefined {
    return this.workflows.get(workflowId);
  }

  /** All tracked workflows, most recently updated first. */
  getAllWorkflows(): WorkflowExecutionContext[] {
    return Array.from(this.workflows.values()).sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** Clears workflow history (clean-baseline reset). */
  reset(): void {
    this.workflows.clear();
  }

  /**
   * Resolves a tool's capability profile from the custom registry, falling back
   * to the shared capability model so authorization and sequence analysis always
   * agree on what a tool does.
   */
  getToolProfile(toolName: string, description?: string): ToolCapabilityProfile {
    const cleanName = stripServerPrefix(toolName);
    const custom = this.customProfiles.get(cleanName.toLowerCase());
    if (custom) return custom;
    return classifyTool(cleanName, description);
  }

  /**
   * Gets or initializes an execution context for a workflow.
   */
  getOrCreateWorkflowContext(
    workflowId: string,
    userId: string,
    agentId?: string,
    intent?: string,
  ): WorkflowExecutionContext {
    let ctx = this.workflows.get(workflowId);
    if (!ctx) {
      ctx = {
        workflowId,
        userId,
        agentId: agentId ?? "llm-agent",
        intent: intent ?? "General security operation",
        toolCallHistory: [],
        capabilityHistory: [],
        resourcesAccessed: new Set<string>(),
        dataSensitivity: "PUBLIC",
        activeLeases: new Set<string>(),
        riskScore: 0,
        securityState: "NORMAL",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      this.workflows.set(workflowId, ctx);
    }
    return ctx;
  }

  /**
   * Core Contextual Tool-Call Evaluation.
   * Evaluates if the current tool call is reasonable given prior tool calls, intent,
   * and capability transitions.
   */
  evaluateToolCall(params: {
    workflowId: string;
    userId: string;
    agentId?: string;
    intent?: string;
    server: string;
    tool: string;
    toolId: string;
    args: unknown;
  }): ContextualEvaluationResult {
    const workflow = this.getOrCreateWorkflowContext(
      params.workflowId,
      params.userId,
      params.agentId,
      params.intent,
    );

    const profile = this.getToolProfile(params.tool);
    const prevCall = workflow.toolCallHistory[workflow.toolCallHistory.length - 1];
    const prevCapability = prevCall?.capability;
    const currentCapability = profile.primaryCapability;

    let riskIncrement = 0;
    let isDangerousSequence = false;
    let intentAligned = true;
    let action: ContextualEvaluationResult["action"] = "allow";
    let reason = "Tool call and capability transition conform to workflow baseline.";

    // ── 1. Capability Transition Analysis ──
    const transitionResult = this.analyzeTransition(prevCapability, currentCapability, workflow.capabilityHistory);

    if (transitionResult.isDangerousSequence) {
      isDangerousSequence = true;
      riskIncrement += transitionResult.riskIncrement;
      action = "block";
      reason = transitionResult.reason ?? "Dangerous capability transition detected.";
    }

    // ── 2. Intent-to-Action Congruence Check ──
    // e.g. Intent: "Investigate suspicious activity from 10.10.20.30"
    const lowerIntent = workflow.intent.toLowerCase();
    const isInvestigation = lowerIntent.includes("investigate") || lowerIntent.includes("audit") || lowerIntent.includes("analyze");

    if (isInvestigation) {
      // Investigation workflows should not transfer data externally or access unrelated credentials
      if (currentCapability === "DATA_TRANSFER") {
        intentAligned = false;
        isDangerousSequence = true;
        riskIncrement += 40;
        action = "block";
        reason = transitionResult.isDangerousSequence && transitionResult.reason
          ? transitionResult.reason
          : `Dangerous sequence detected: Workflow intent "${workflow.intent}" does not permit external data transfer (DATA_TRANSFER).`;
      } else if (currentCapability === "SECRET_ACCESS" && workflow.capabilityHistory.includes("EXTERNAL_LOOKUP")) {
        intentAligned = false;
        isDangerousSequence = true;
        riskIncrement += 35;
        // Suspicious, but not irreversible: an incident responder can legitimately
        // need credentials mid-investigation. Escalate to a human rather than
        // hard-blocking. The irreversible step (external transfer) is what gets
        // the hard block, below.
        action = "require-approval";
        reason = `Contextual Anomaly: Reconnaissance (EXTERNAL_LOOKUP) followed by credential access (SECRET_ACCESS) in an investigation workflow — human approval required.`;
      }
    }

    // ── 3. Approval Gate Requirement ──
    if (action === "allow" && profile.requiresApproval) {
      action = "require-approval";
      reason = `Tool "${profile.toolName}" requires human supervisor approval (Capability: ${profile.primaryCapability}).`;
    }

    return {
      action,
      reason,
      isDangerousSequence,
      intentAligned,
      capabilityTransition: transitionResult,
      riskIncrement,
      workflowContext: workflow,
    };
  }

  /**
   * Records a successfully executed (or attempted) tool call into the workflow context.
   */
  recordCall(
    workflowId: string,
    toolId: string,
    toolName: string,
    server: string,
    args: unknown,
    decision: "allow" | "block" | "require-approval",
    riskScore: number,
  ): void {
    const workflow = this.getOrCreateWorkflowContext(workflowId, "system", "agent");

    const profile = this.getToolProfile(toolName);
    const record: ToolCallRecord = {
      toolId,
      toolName,
      server,
      capability: profile.primaryCapability,
      args,
      timestamp: Date.now(),
      decision,
      riskScore,
    };

    workflow.toolCallHistory.push(record);
    workflow.capabilityHistory.push(profile.primaryCapability);
    workflow.riskScore = riskScore;
    workflow.updatedAt = Date.now();
  }

  /**
   * Analyzes transitions between capabilities for dangerous sequences.
   */
  private analyzeTransition(
    from?: CapabilityType,
    to: CapabilityType = "UNKNOWN",
    history: CapabilityType[] = [],
  ): CapabilityTransitionResult {
    if (!from) {
      return { allowed: true, toCapability: to, riskIncrement: 0, isDangerousSequence: false };
    }

    // Pattern A: Reconnaissance -> Secret Access -> Data Transfer (Classic Exfiltration Chain)
    const hasRecon = history.includes("READ") || history.includes("EXTERNAL_LOOKUP");
    const hasSecretAccess = history.includes("SECRET_ACCESS") || from === "SECRET_ACCESS";

    if (hasRecon && hasSecretAccess && to === "DATA_TRANSFER") {
      return {
        allowed: false,
        fromCapability: from,
        toCapability: to,
        riskIncrement: 45,
        isDangerousSequence: true,
        reason: "Dangerous sequence detected: Reconnaissance -> Secret Access -> External Data Transfer (ATT&CK Exfiltration)",
      };
    }

    // Pattern B: Reconnaissance -> Data Transfer (Direct Exfiltration)
    if (hasRecon && to === "DATA_TRANSFER" && !history.includes("WRITE")) {
      return {
        allowed: false,
        fromCapability: from,
        toCapability: to,
        riskIncrement: 35,
        isDangerousSequence: true,
        reason: "Suspicious sequence: Reconnaissance immediately followed by external data transfer without incident logging",
      };
    }

    // Pattern C: Secret Access -> Infrastructure Control
    if (from === "SECRET_ACCESS" && to === "INFRASTRUCTURE_CONTROL") {
      return {
        allowed: false,
        fromCapability: from,
        toCapability: to,
        riskIncrement: 40,
        isDangerousSequence: true,
        reason: "High-risk transition: Credential acquisition followed immediately by infrastructure control",
      };
    }

    // Pattern D: Legitimate Investigation Progression (READ -> EXTERNAL_LOOKUP -> WRITE)
    if (
      (from === "READ" && to === "EXTERNAL_LOOKUP") ||
      (from === "EXTERNAL_LOOKUP" && to === "WRITE") ||
      (from === "READ" && to === "WRITE")
    ) {
      return {
        allowed: true,
        fromCapability: from,
        toCapability: to,
        riskIncrement: 0,
        isDangerousSequence: false,
        reason: "Conformant investigation transition: Reconnaissance -> Verification -> Incident Logging",
      };
    }

    return {
      allowed: true,
      fromCapability: from,
      toCapability: to,
      riskIncrement: 0,
      isDangerousSequence: false,
    };
  }
}
