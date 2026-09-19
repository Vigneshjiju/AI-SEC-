/**
 * MCP-Sentinel: Quarantine Manager
 * Manages server quarantine and controlled recovery.
 * A quarantined server is NEVER automatically trusted again.
 */

import type { QuarantineRecord, SecurityEvent } from "./types.js";
import type { ServerRegistry } from "./registry.js";
import type { SecurityStateMachine } from "./state-machine.js";
import type { SentinelEventBus } from "./events.js";

export class QuarantineManager {
  private registry: ServerRegistry;
  private stateMachine: SecurityStateMachine;
  private eventBus: SentinelEventBus;
  private quarantineHistory: QuarantineRecord[] = [];

  constructor(
    registry: ServerRegistry,
    stateMachine: SecurityStateMachine,
    eventBus: SentinelEventBus,
  ) {
    this.registry = registry;
    this.stateMachine = stateMachine;
    this.eventBus = eventBus;
  }

  /**
   * Quarantine a server. Blocks all future tool calls.
   */
  quarantine(
    serverId: string,
    reason: string,
    riskScore: number,
    evidence: string[],
    triggeringEvent: string,
  ): QuarantineRecord | null {
    const server = this.registry.getServer(serverId);
    if (!server) return null;

    const record: QuarantineRecord = {
      serverId,
      serverName: server.serverName,
      reason,
      riskScore,
      evidence,
      timestamp: new Date().toISOString(),
      triggeringEvent,
    };

    this.registry.quarantineServer(serverId, record);
    this.stateMachine.forceTransition(serverId, "QUARANTINE", reason, riskScore);
    this.registry.incrementIncidents(serverId);
    this.quarantineHistory.push(record);

    // Emit event
    this.eventBus.emit({
      id: `evt_${Date.now().toString(36)}`,
      type: "SERVER_QUARANTINED",
      timestamp: record.timestamp,
      serverId,
      serverName: server.serverName,
      riskScore,
      riskDelta: 0,
      securityState: "QUARANTINE",
      previousState: server.securityState,
      decision: "QUARANTINE",
      reasons: [reason],
      evidence,
      policy: "quarantine-manager",
    });

    process.stderr.write(`[sentinel] 🔴 Server "${server.serverName}" QUARANTINED: ${reason}\n`);
    return record;
  }

  /**
   * Controlled recovery. Never returns to NORMAL — always MONITOR.
   */
  recover(serverId: string, approvedBy: string, reason?: string): boolean {
    const server = this.registry.getServer(serverId);
    if (!server || !this.registry.isQuarantined(serverId)) return false;

    this.registry.recoverServer(serverId, approvedBy);
    this.stateMachine.forceTransition(serverId, "MONITOR",
      reason ? `${reason} (Approved by ${approvedBy})` : `Recovered from quarantine by ${approvedBy}`,
      server.currentRisk);

    // Emit event
    this.eventBus.emit({
      id: `evt_${Date.now().toString(36)}`,
      type: "SERVER_RECOVERED",
      timestamp: new Date().toISOString(),
      serverId,
      serverName: server.serverName,
      riskScore: server.currentRisk,
      riskDelta: 0,
      securityState: "MONITOR",
      previousState: "QUARANTINE",
      decision: "RECOVER",
      reasons: [`Recovery approved by ${approvedBy}`],
      evidence: [],
      policy: "quarantine-manager",
    });

    process.stderr.write(`[sentinel] 🟡 Server "${server.serverName}" recovered from quarantine → MONITOR\n`);
    return true;
  }

  /**
   * Check if a server is quarantined.
   */
  isQuarantined(serverId: string): boolean {
    return this.registry.isQuarantined(serverId);
  }

  /**
   * Get quarantine history.
   */
  getHistory(): QuarantineRecord[] {
    return [...this.quarantineHistory];
  }

  /**
   * Get active quarantines.
   */
  getActiveQuarantines(): QuarantineRecord[] {
    return this.quarantineHistory.filter(r => !r.recoveredAt);
  }
}
