/**
 * MCP-Sentinel: Server & Tool Registry
 * Stores security metadata for MCP servers and tools.
 * Registration creates an initial security profile, NOT permanent trust.
 */

import { createHash } from "node:crypto";
import type {
  ServerRegistration,
  ToolRegistration,
  BehaviorFingerprint,
  CapabilitySet,
  TrustStatus,
  SecurityState,
  QuarantineRecord,
  ToolState,
  createEmptyCapabilitySet as CreateEmptyCapabilitySetFn,
} from "./types.js";
import { createEmptyCapabilitySet, createEmptyFingerprint } from "./types.js";

let idCounter = 0;
function generateId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${(++idCounter).toString(36)}`;
}

export class ServerRegistry {
  private servers: Map<string, ServerRegistration> = new Map();
  private tools: Map<string, ToolRegistration> = new Map();
  private serversByName: Map<string, string> = new Map();

  registerServer(name: string, opts: {
    serverName?: string;
    version?: string;
    source?: string;
    transport?: "stdio" | "http" | "sse";
  } = {}): ServerRegistration {
    // Check if already registered
    const existing = this.serversByName.get(name);
    if (existing) {
      const server = this.servers.get(existing)!;
      if (opts.serverName) server.serverName = opts.serverName;
      server.lastSeen = new Date().toISOString();
      return server;
    }

    const serverId = generateId("srv");
    const server: ServerRegistration = {
      serverId,
      serverName: opts.serverName ?? name,
      version: opts.version ?? "unknown",
      source: opts.source ?? "local",
      transport: opts.transport ?? "stdio",
      trustStatus: "PROVISIONAL",
      baselineHash: "",
      lastSeen: new Date().toISOString(),
      currentRisk: 0,
      securityState: "NORMAL",
      quarantineStatus: null,
      registeredAt: new Date().toISOString(),
      toolIds: [],
      incidentCount: 0,
    };

    this.servers.set(serverId, server);
    this.serversByName.set(name, serverId);
    return server;
  }

  registerTool(serverId: string, name: string, opts: {
    description?: string;
    inputSchema?: unknown;
    declaredCapabilities?: Partial<CapabilitySet>;
    criticality?: ToolRegistration["criticality"];
    sensitivity?: ToolRegistration["sensitivity"];
  } = {}): ToolRegistration {
    const server = this.getServer(serverId);
    if (!server) throw new Error(`Server ${serverId} not found`);

    // Check if tool already registered
    const existingId = server.toolIds.find(id => {
      const t = this.tools.get(id);
      return t && t.toolName === name;
    });
    if (existingId) {
      const tool = this.tools.get(existingId)!;
      tool.description = opts.description ?? tool.description;
      return tool;
    }

    const toolId = generateId("tool");
    const tool: ToolRegistration = {
      toolId,
      toolName: name,
      serverId,
      description: opts.description ?? "",
      inputSchema: opts.inputSchema ?? {},
      declaredCapabilities: { ...createEmptyCapabilitySet(), ...opts.declaredCapabilities },
      authorizedCapabilities: { ...createEmptyCapabilitySet(), ...opts.declaredCapabilities },
      baselineFingerprint: null,
      currentFingerprint: null,
      riskScore: 0,
      criticality: opts.criticality ?? "medium",
      sensitivity: opts.sensitivity ?? "internal",
      state: "ACTIVE",
      callCount: 0,
      lastCalledAt: null,
    };

    this.tools.set(toolId, tool);
    server.toolIds.push(toolId);
    return tool;
  }

  setBaseline(toolId: string, fingerprint: BehaviorFingerprint): void {
    const tool = this.tools.get(toolId);
    if (!tool) return;
    tool.baselineFingerprint = { ...fingerprint };
    tool.currentFingerprint = { ...fingerprint };

    const server = this.servers.get(tool.serverId);
    if (server) {
      server.baselineHash = createHash("sha256")
        .update(JSON.stringify(fingerprint))
        .digest("hex");
    }
  }

  updateFingerprint(toolId: string, fingerprint: BehaviorFingerprint): void {
    const tool = this.tools.get(toolId);
    if (!tool) return;
    tool.currentFingerprint = fingerprint;
  }

  updateToolRisk(toolId: string, score: number): void {
    const tool = this.tools.get(toolId);
    if (!tool) return;
    tool.riskScore = score;
  }

  updateServerRisk(serverId: string, score: number, state: SecurityState): void {
    const server = this.servers.get(serverId);
    if (!server) return;
    server.currentRisk = score;
    server.securityState = state;
  }

  updateServerTrust(serverId: string, status: TrustStatus): void {
    const server = this.servers.get(serverId);
    if (!server) return;
    server.trustStatus = status;
  }

  updateToolState(toolId: string, state: ToolState): void {
    const tool = this.tools.get(toolId);
    if (!tool) return;
    tool.state = state;
  }

  recordToolCall(toolId: string): void {
    const tool = this.tools.get(toolId);
    if (!tool) return;
    tool.callCount++;
    tool.lastCalledAt = new Date().toISOString();
  }

  incrementIncidents(serverId: string): void {
    const server = this.servers.get(serverId);
    if (server) server.incidentCount++;
  }

  // ── Queries ──

  getServer(serverId: string): ServerRegistration | undefined {
    return this.servers.get(serverId) ?? this.getServerByName(serverId);
  }

  getServerByName(name: string): ServerRegistration | undefined {
    const id = this.serversByName.get(name);
    return id ? this.servers.get(id) : undefined;
  }

  getTool(toolId: string): ToolRegistration | undefined {
    return this.tools.get(toolId);
  }

  getToolByName(serverId: string, toolName: string): ToolRegistration | undefined {
    const server = this.servers.get(serverId);
    if (!server) return undefined;
    for (const tid of server.toolIds) {
      const tool = this.tools.get(tid);
      if (tool && tool.toolName === toolName) return tool;
    }
    return undefined;
  }

  getToolByPrefixedName(prefixedName: string): ToolRegistration | undefined {
    for (const tool of this.tools.values()) {
      const server = this.servers.get(tool.serverId);
      if (server && `${server.serverName}__${tool.toolName}` === prefixedName) {
        return tool;
      }
    }
    return undefined;
  }

  getAllServers(): ServerRegistration[] {
    return Array.from(this.servers.values());
  }

  getAllTools(): ToolRegistration[] {
    return Array.from(this.tools.values());
  }

  getServerTools(serverId: string): ToolRegistration[] {
    const server = this.servers.get(serverId);
    if (!server) return [];
    return server.toolIds.map(id => this.tools.get(id)).filter(Boolean) as ToolRegistration[];
  }

  isQuarantined(serverId: string): boolean {
    const server = this.servers.get(serverId);
    return server?.quarantineStatus !== null && server?.quarantineStatus !== undefined
      && !server.quarantineStatus.recoveredAt;
  }

  quarantineServer(serverId: string, record: QuarantineRecord): void {
    const server = this.servers.get(serverId);
    if (!server) return;
    server.quarantineStatus = record;
    server.trustStatus = "QUARANTINED";
    server.securityState = "QUARANTINE";
    // Mark all tools as quarantined
    for (const tid of server.toolIds) {
      const tool = this.tools.get(tid);
      if (tool) tool.state = "QUARANTINED";
    }
  }

  recoverServer(serverId: string, approvedBy: string): void {
    const server = this.servers.get(serverId);
    if (!server || !server.quarantineStatus) return;
    server.quarantineStatus.recoveredAt = new Date().toISOString();
    server.quarantineStatus.recoveredBy = approvedBy;
    server.trustStatus = "SUSPICIOUS"; // Never back to TRUSTED directly
    server.securityState = "MONITOR"; // Always return to MONITOR
    // Mark tools as restricted (not fully active)
    for (const tid of server.toolIds) {
      const tool = this.tools.get(tid);
      if (tool) tool.state = "RESTRICTED";
    }
  }
}
