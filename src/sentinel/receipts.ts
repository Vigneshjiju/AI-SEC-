/**
 * MCP-Sentinel: Verifiable Decision Receipts Ledger
 * 
 * Generates and stores explainable, tamper-evident decision receipts
 * for every security policy evaluation, restriction, and blocking action.
 */

import { DecisionReceipt, SecurityState, CapabilityType } from "./types.js";
import { createHash } from "node:crypto";
import { appendFile } from "node:fs/promises";

export class DecisionReceiptsLedger {
  private receipts: Map<string, DecisionReceipt> = new Map();
  private auditFilePath?: string;

  constructor(auditFilePath?: string) {
    this.auditFilePath = auditFilePath;
  }

  /**
   * Generates, hashes, and records an explainable decision receipt.
   */
  async recordReceipt(params: {
    workflowId: string;
    tool: string;
    toolId: string;
    server: string;
    decision: DecisionReceipt["decision"];
    riskScore: number;
    state: SecurityState;
    reasons: string[];
    evidence: string[];
    previousTools: string[];
    capabilityTransitions: { from?: CapabilityType; to: CapabilityType }[];
    activeLeaseId?: string;
  }): Promise<DecisionReceipt> {
    const timestamp = new Date().toISOString();
    const receiptId = `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;

    // Build raw payload for canonical hashing
    const canonicalPayload = JSON.stringify({
      receiptId,
      workflowId: params.workflowId,
      tool: params.tool,
      server: params.server,
      decision: params.decision,
      riskScore: params.riskScore,
      reasons: params.reasons,
      timestamp,
    });

    const hash = createHash("sha256").update(canonicalPayload).digest("hex");

    const receipt: DecisionReceipt = {
      receiptId,
      workflowId: params.workflowId,
      tool: params.tool,
      toolId: params.toolId,
      server: params.server,
      decision: params.decision,
      riskScore: params.riskScore,
      state: params.state,
      reasons: params.reasons,
      evidence: params.evidence,
      previousTools: params.previousTools,
      capabilityTransitions: params.capabilityTransitions,
      activeLeaseId: params.activeLeaseId,
      timestamp,
      hash,
    };

    this.receipts.set(receiptId, receipt);

    // Optional persistent audit trail
    if (this.auditFilePath) {
      try {
        await appendFile(this.auditFilePath, JSON.stringify(receipt) + "\n", "utf8");
      } catch {
        // Silently continue in-memory if disk write encounters permissions
      }
    }

    return receipt;
  }

  /**
   * Synchronous version for real-time decision flows.
   */
  recordReceiptSync(params: {
    workflowId: string;
    tool: string;
    toolId: string;
    server: string;
    decision: DecisionReceipt["decision"];
    riskScore: number;
    state: SecurityState;
    reasons: string[];
    evidence: string[];
    previousTools: string[];
    capabilityTransitions: { from?: CapabilityType; to: CapabilityType }[];
    activeLeaseId?: string;
  }): DecisionReceipt {
    const timestamp = new Date().toISOString();
    const receiptId = `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;

    const canonicalPayload = JSON.stringify({
      receiptId,
      workflowId: params.workflowId,
      tool: params.tool,
      server: params.server,
      decision: params.decision,
      riskScore: params.riskScore,
      reasons: params.reasons,
      timestamp,
    });

    const hash = createHash("sha256").update(canonicalPayload).digest("hex");

    const receipt: DecisionReceipt = {
      receiptId,
      workflowId: params.workflowId,
      tool: params.tool,
      toolId: params.toolId,
      server: params.server,
      decision: params.decision,
      riskScore: params.riskScore,
      state: params.state,
      reasons: params.reasons,
      evidence: params.evidence,
      previousTools: params.previousTools,
      capabilityTransitions: params.capabilityTransitions,
      activeLeaseId: params.activeLeaseId,
      timestamp,
      hash,
    };

    this.receipts.set(receiptId, receipt);
    return receipt;
  }

  getReceipt(receiptId: string): DecisionReceipt | undefined {
    return this.receipts.get(receiptId);
  }

  getReceiptsForWorkflow(workflowId: string): DecisionReceipt[] {
    return Array.from(this.receipts.values()).filter((r) => r.workflowId === workflowId);
  }

  getAllReceipts(): DecisionReceipt[] {
    return Array.from(this.receipts.values()).sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }
}
