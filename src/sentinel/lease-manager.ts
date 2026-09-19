/**
 * MCP-Sentinel: Capability Lease Manager
 * 
 * Manages time-bounded, workflow-scoped temporary capability leases.
 * Prevents tools from acquiring permanent unrestricted permissions.
 * 
 * Automatically revokes leases upon:
 * - Critical risk escalation (risk >= 75)
 * - Workflow termination or intent completion
 * - Behavioral drift or capability mismatch detection
 * - Server quarantine or integrity violation
 */

import { CapabilityLease, LeaseState } from "./types.js";
import { SentinelEventBus } from "./events.js";

export class CapabilityLeaseManager {
  private leases: Map<string, CapabilityLease> = new Map();
  private eventBus?: SentinelEventBus;

  constructor(eventBus?: SentinelEventBus) {
    this.eventBus = eventBus;
  }

  /**
   * Issues a temporary capability lease for a tool within a specific workflow scope.
   */
  issueLease(params: {
    toolId: string;
    toolName: string;
    capability: string;
    scope: string;
    workflowId: string;
    userId: string;
    ttlSeconds?: number;
  }): CapabilityLease {
    const ttl = params.ttlSeconds ?? 600; // Default 10 minutes
    const now = Date.now();
    const leaseId = `lease_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;

    const lease: CapabilityLease = {
      leaseId,
      toolId: params.toolId,
      toolName: params.toolName,
      capability: params.capability,
      scope: params.scope,
      workflowId: params.workflowId,
      userId: params.userId,
      issuedAt: now,
      expiresAt: now + ttl * 1000,
      state: "ACTIVE",
    };

    this.leases.set(leaseId, lease);
    return lease;
  }

  /**
   * Retrieves a lease by ID and updates its state if expired.
   */
  getLease(leaseId: string): CapabilityLease | undefined {
    const lease = this.leases.get(leaseId);
    if (!lease) return undefined;

    if (lease.state === "ACTIVE" || lease.state === "EXPIRING") {
      const remainingMs = lease.expiresAt - Date.now();
      if (remainingMs <= 0) {
        lease.state = "EXPIRED";
      } else if (remainingMs < 60000) {
        lease.state = "EXPIRING";
      }
    }

    return lease;
  }

  /**
   * Validates whether a tool call has an active lease for the requested capability and workflow.
   */
  validateLease(params: {
    leaseId?: string;
    toolId: string;
    capability: string;
    workflowId?: string;
  }): { valid: boolean; lease?: CapabilityLease; reason?: string } {
    // If a specific leaseId was passed, verify it directly
    if (params.leaseId) {
      const lease = this.getLease(params.leaseId);
      if (!lease) {
        return { valid: false, reason: `Lease "${params.leaseId}" not found` };
      }
      if (lease.state === "REVOKED") {
        return { valid: false, lease, reason: `Capability lease revoked: ${lease.revocationReason}` };
      }
      if (lease.state === "EXPIRED" || Date.now() > lease.expiresAt) {
        lease.state = "EXPIRED";
        return { valid: false, lease, reason: `Capability lease expired at ${new Date(lease.expiresAt).toISOString()}` };
      }
      if (lease.toolId !== params.toolId) {
        return { valid: false, lease, reason: `Lease belongs to tool ${lease.toolName}, not ${params.toolId}` };
      }
      if (params.workflowId && lease.workflowId !== params.workflowId) {
        return { valid: false, lease, reason: `Lease belongs to workflow ${lease.workflowId}, not ${params.workflowId}` };
      }
      return { valid: true, lease };
    }

    // Otherwise, look for an active matching lease for this tool, capability, and workflow
    for (const lease of this.leases.values()) {
      if (
        lease.toolId === params.toolId &&
        lease.capability.toLowerCase() === params.capability.toLowerCase() &&
        (!params.workflowId || lease.workflowId === params.workflowId)
      ) {
        if (lease.state === "ACTIVE" || lease.state === "EXPIRING") {
          if (Date.now() <= lease.expiresAt) {
            return { valid: true, lease };
          }
          lease.state = "EXPIRED";
        }
      }
    }

    return {
      valid: false,
      reason: `No active capability lease found for tool "${params.toolId}" with capability "${params.capability}"`,
    };
  }

  /**
   * Explicitly revokes a capability lease.
   */
  revokeLease(leaseId: string, reason: string): boolean {
    const lease = this.leases.get(leaseId);
    if (!lease) return false;

    lease.state = "REVOKED";
    lease.revokedAt = Date.now();
    lease.revocationReason = reason;

    return true;
  }

  /**
   * Automatically revokes all capability leases associated with a workflow
   * (e.g. when workflow completes or critical risk is reached).
   */
  revokeAllForWorkflow(workflowId: string, reason: string): number {
    let count = 0;
    for (const lease of this.leases.values()) {
      if (lease.workflowId === workflowId && lease.state !== "REVOKED" && lease.state !== "EXPIRED") {
        lease.state = "REVOKED";
        lease.revokedAt = Date.now();
        lease.revocationReason = reason;
        count++;
      }
    }
    return count;
  }

  /**
   * Automatically revokes all leases for a specific tool
   * (e.g. when tool is quarantined or exhibits behavioral drift).
   */
  revokeAllForTool(toolId: string, reason: string): number {
    let count = 0;
    for (const lease of this.leases.values()) {
      if (lease.toolId === toolId && lease.state !== "REVOKED" && lease.state !== "EXPIRED") {
        lease.state = "REVOKED";
        lease.revokedAt = Date.now();
        lease.revocationReason = reason;
        count++;
      }
    }
    return count;
  }

  /**
   * Handles risk escalation: if risk >= 75 (quarantine threshold),
   * revokes all active leases for the offending tool and workflow.
   */
  onRiskEscalation(toolId: string, workflowId: string | undefined, riskScore: number): number {
    if (riskScore >= 75) {
      let revoked = this.revokeAllForTool(toolId, `Risk score escalated to ${riskScore}/100 (>= 75 critical threshold)`);
      if (workflowId) {
        revoked += this.revokeAllForWorkflow(workflowId, `Workflow terminated due to critical risk escalation (${riskScore}/100)`);
      }
      return revoked;
    }
    return 0;
  }

  /**
   * Lists all active capability leases.
   */
  getActiveLeases(): CapabilityLease[] {
    const now = Date.now();
    return Array.from(this.leases.values()).filter((l) => {
      if (l.state === "REVOKED") return false;
      if (now > l.expiresAt) {
        l.state = "EXPIRED";
        return false;
      }
      return true;
    });
  }
}
