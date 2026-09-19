/**
 * MCP-Sentinel: Multi-Signal Threat Detector
 * 
 * Correlates signals across:
 * - Identity verification
 * - Tool descriptor integrity
 * - Semantic change firewall
 * - Workflow context & capability transitions
 * - Continuous behavioral runtime deviation
 * - Data-flow guard taint tracking
 * - Pre-execution input validation
 * - Post-execution output validation
 * 
 * Detects:
 * TOOL_POISONING, TOOL_DEFINITION_MODIFICATION, PRIVILEGE_ESCALATION,
 * CREDENTIAL_ACCESS, DATA_EXFILTRATION, WORKFLOW_ABUSE_SEQUENCE,
 * PROMPT_INJECTION, ABNORMAL_BEHAVIOR, UNAUTHORIZED_RESOURCE_ACCESS
 */

import { ThreatSignal, ThreatType, SecurityState, SemanticDiffResult, BehaviorDriftFinding } from "./types.js";
import { InputValidationResult } from "./input-validator.js";
import { ContextualEvaluationResult } from "./contextual-engine.js";
import { SecurityFinding } from "../types/index.js";

export class ThreatDetector {
  /**
   * Correlates multi-source evidence to generate synthesized threat signals.
   */
  correlateThreats(params: {
    identityVerified: boolean;
    identityError?: string;
    inputValidation?: InputValidationResult;
    semanticDiff?: SemanticDiffResult;
    contextualEvaluation?: ContextualEvaluationResult;
    dataFlowViolation?: { reason: string };
    driftFindings?: BehaviorDriftFinding[];
    outputFindings?: SecurityFinding[];
    descriptorChanged?: boolean;
  }): ThreatSignal[] {
    const signals: ThreatSignal[] = [];
    const now = new Date().toISOString();

    // 1. Identity Verification Signals
    if (!params.identityVerified && params.identityError) {
      signals.push({
        threatType: "PRIVILEGE_ESCALATION",
        severity: "high",
        source: "identity",
        confidence: 0.95,
        message: `Identity verification failure: ${params.identityError}`,
        evidence: { error: params.identityError },
        timestamp: now,
      });
    }

    // 2. Input Validation Signals
    if (params.inputValidation && !params.inputValidation.valid) {
      for (const v of params.inputValidation.violations) {
        signals.push({
          threatType: "TOOL_POISONING",
          severity: v.severity,
          source: "input",
          confidence: 0.9,
          message: `Hostile input detected (${v.ruleId}): ${v.message}`,
          evidence: v,
          timestamp: now,
        });
      }
    }

    // 3. Tool Definition & Semantic Tampering
    if (params.descriptorChanged) {
      signals.push({
        threatType: "TOOL_DEFINITION_MODIFICATION",
        severity: "critical",
        source: "integrity",
        confidence: 1.0,
        message: "Tool descriptor cryptographic hash mismatch against baseline",
        evidence: { descriptorChanged: true },
        timestamp: now,
      });
    }

    if (params.semanticDiff && params.semanticDiff.hasSemanticChange) {
      for (const f of params.semanticDiff.findings) {
        signals.push({
          threatType: "TOOL_DEFINITION_MODIFICATION",
          severity: f.severity,
          source: "semantic",
          confidence: 0.85,
          message: `Semantic Change Firewall detected: ${f.description}`,
          evidence: f.details,
          timestamp: now,
        });
      }
    }

    // 4. Workflow Abuse & Capability Transition Anomaly
    if (params.contextualEvaluation && params.contextualEvaluation.isDangerousSequence) {
      const isExfil = params.contextualEvaluation.capabilityTransition.toCapability === "DATA_TRANSFER";
      signals.push({
        threatType: isExfil ? "DATA_EXFILTRATION" : "WORKFLOW_ABUSE_SEQUENCE",
        severity: "critical",
        source: "transition",
        confidence: 0.95,
        message: params.contextualEvaluation.reason,
        evidence: {
          transition: params.contextualEvaluation.capabilityTransition,
          history: params.contextualEvaluation.workflowContext.capabilityHistory,
        },
        timestamp: now,
      });
    }

    // 5. Data-Flow Taint Exfiltration
    if (params.dataFlowViolation) {
      signals.push({
        threatType: "DATA_EXFILTRATION",
        severity: "critical",
        source: "dataflow",
        confidence: 0.98,
        message: params.dataFlowViolation.reason,
        evidence: params.dataFlowViolation,
        timestamp: now,
      });
    }

    // 6. Behavioral Drift Anomalies
    if (params.driftFindings && params.driftFindings.length > 0) {
      for (const drift of params.driftFindings) {
        let threatType: ThreatType = "ABNORMAL_BEHAVIOR";
        if (drift.type === "NEW_EXTERNAL_NETWORK") threatType = "DATA_EXFILTRATION";
        if (drift.type === "NEW_FILESYSTEM_ACCESS") threatType = "UNAUTHORIZED_RESOURCE_ACCESS";
        if (drift.type === "CAPABILITY_MISMATCH") threatType = "PRIVILEGE_ESCALATION";

        signals.push({
          threatType,
          severity: drift.severity,
          source: "behavior",
          confidence: 0.9,
          message: drift.message,
          evidence: drift.evidence,
          timestamp: now,
        });
      }
    }

    // 7. Output Validation (Prompt Injections & Leaked Secrets)
    if (params.outputFindings && params.outputFindings.length > 0) {
      for (const f of params.outputFindings) {
        let threatType: ThreatType = "PROMPT_INJECTION";
        if (f.ruleId.includes("secret") || f.ruleId.includes("token") || f.ruleId.includes("key")) {
          threatType = "CREDENTIAL_ACCESS";
        }
        signals.push({
          threatType,
          severity: f.severity,
          source: "output",
          confidence: 0.88,
          message: f.message,
          evidence: f,
          timestamp: now,
        });
      }
    }

    return signals;
  }
}
