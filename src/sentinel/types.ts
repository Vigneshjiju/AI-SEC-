/**
 * MCP-Sentinel Core Type Definitions
 * Adaptive Security Control Plane for Model Context Protocol
 */

// ── Security States ──

export type SecurityState = "NORMAL" | "MONITOR" | "RESTRICT" | "HUMAN_APPROVAL" | "QUARANTINE";

export type TrustStatus = "TRUSTED" | "PROVISIONAL" | "SUSPICIOUS" | "UNTRUSTED" | "QUARANTINED";

export type ToolState = "ACTIVE" | "RESTRICTED" | "SUSPENDED" | "QUARANTINED";

// ── Server & Tool Registration ──

export interface ServerRegistration {
  serverId: string;
  serverName: string;
  version: string;
  source: string;
  transport: "stdio" | "http" | "sse";
  trustStatus: TrustStatus;
  baselineHash: string;
  lastSeen: string;
  currentRisk: number;
  securityState: SecurityState;
  quarantineStatus: QuarantineRecord | null;
  registeredAt: string;
  toolIds: string[];
  incidentCount: number;
}

export interface ToolRegistration {
  toolId: string;
  toolName: string;
  serverId: string;
  description: string;
  inputSchema: unknown;
  declaredCapabilities: CapabilitySet;
  authorizedCapabilities: CapabilitySet;
  baselineFingerprint: BehaviorFingerprint | null;
  currentFingerprint: BehaviorFingerprint | null;
  riskScore: number;
  criticality: "low" | "medium" | "high" | "critical";
  sensitivity: "public" | "internal" | "confidential" | "restricted";
  state: ToolState;
  callCount: number;
  lastCalledAt: string | null;
}

// ── Capability Model ──

export interface CapabilitySet {
  filesystem: string[];
  network: string[];
  processes: string[];
  envAccess: boolean;
  externalNetwork: boolean;
  sensitiveFileAccess: boolean;
  commandExecution: boolean;
}

export function createEmptyCapabilitySet(): CapabilitySet {
  return {
    filesystem: [],
    network: [],
    processes: [],
    envAccess: false,
    externalNetwork: false,
    sensitiveFileAccess: false,
    commandExecution: false,
  };
}

// ── Behavior Fingerprint ──

export interface BehaviorFingerprint {
  toolId: string;
  timestamp: string;
  filesystem: string[];
  network: string[];
  processes: string[];
  envAccess: boolean;
  externalNetwork: boolean;
  sensitiveFileAccess: boolean;
  commandExecution: boolean;
  outputPatterns: string[];
  avgResponseTimeMs: number;
  callFrequencyPerMin: number;
  dataSensitivity: "low" | "medium" | "high";
}

export function createEmptyFingerprint(toolId: string): BehaviorFingerprint {
  return {
    toolId,
    timestamp: new Date().toISOString(),
    filesystem: [],
    network: [],
    processes: [],
    envAccess: false,
    externalNetwork: false,
    sensitiveFileAccess: false,
    commandExecution: false,
    outputPatterns: [],
    avgResponseTimeMs: 0,
    callFrequencyPerMin: 0,
    dataSensitivity: "low",
  };
}

// ── Behavior Drift ──

export type DriftType =
  | "BEHAVIOR_DRIFT"
  | "NEW_FILESYSTEM_ACCESS"
  | "NEW_ENVIRONMENT_ACCESS"
  | "NEW_EXTERNAL_NETWORK"
  | "NEW_PROCESS_EXECUTION"
  | "CAPABILITY_MISMATCH"
  | "NEW_COMMAND_EXECUTION"
  | "SENSITIVE_FILE_ACCESS"
  | "OUTPUT_PATTERN_CHANGE"
  | "FREQUENCY_ANOMALY";

export interface BehaviorDriftFinding {
  type: DriftType;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  evidence: string;
  baselineValue?: string;
  observedValue?: string;
  riskContribution: number;
}

// ── Risk Assessment ──

export interface RiskAssessment {
  score: number;
  previousScore: number;
  delta: number;
  state: SecurityState;
  reasons: string[];
  factors: RiskFactors;
  timestamp: string;
  toolId?: string;
  serverId?: string;
}

export interface RiskFactors {
  integrity: number;
  behavior: number;
  runtime: number;
  authorization: number;
  sensitivity: number;
  anomaly: number;
}

export interface RiskWeights {
  integrity: number;
  behavior: number;
  runtime: number;
  authorization: number;
  sensitivity: number;
  anomaly: number;
}

// ── Policy ──

export interface PolicyDecision {
  action: "allow" | "block" | "restrict" | "require-approval" | "quarantine";
  reason: string;
  evidence: string[];
  policy: string;
  riskScore: number;
  securityState: SecurityState;
  timestamp: string;
  isHardRule: boolean;
}

export interface ApprovalRequest {
  id: string;
  serverId: string;
  toolId: string;
  toolName: string;
  userId: string;
  userRole: string;
  action: string;
  args: unknown;
  riskScore: number;
  reasons: string[];
  createdAt: string;
  expiresAt: string;
  status: "pending" | "approved" | "denied" | "expired";
  decidedBy?: string;
  decidedAt?: string;
}

// ── Quarantine ──

export interface QuarantineRecord {
  serverId: string;
  serverName: string;
  reason: string;
  riskScore: number;
  evidence: string[];
  timestamp: string;
  triggeringEvent: string;
  recoveredAt?: string;
  recoveredBy?: string;
}

// ── Security Events ──

export type SecurityEventType =
  | "RISK_CHANGE"
  | "STATE_TRANSITION"
  | "BEHAVIOR_DRIFT"
  | "TOOL_ALLOWED"
  | "TOOL_BLOCKED"
  | "TOOL_RESTRICTED"
  | "SERVER_QUARANTINED"
  | "SERVER_RECOVERED"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_GRANTED"
  | "APPROVAL_DENIED"
  | "CAPABILITY_VIOLATION"
  | "BASELINE_CREATED"
  | "FINGERPRINT_UPDATED"
  | "OUTPUT_ANOMALY";

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  timestamp: string;
  serverId: string;
  serverName: string;
  toolId?: string;
  toolName?: string;
  userId?: string;
  riskScore: number;
  riskDelta: number;
  securityState: SecurityState;
  previousState?: SecurityState;
  decision?: string;
  reasons: string[];
  evidence: string[];
  policy?: string;
  driftFindings?: BehaviorDriftFinding[];
}

// ── Auth ──

export interface UserIdentity {
  userId: string;
  username: string;
  role: "viewer" | "analyst" | "incident_responder" | "admin";
  permissions: string[];
}

// ── Sentinel Configuration ──

export interface SentinelConfig {
  risk: {
    thresholds: {
      monitor: number;
      restrict: number;
      approval: number;
      quarantine: number;
    };
    weights: RiskWeights;
    hysteresis: {
      margin: number;
      cooldownMs: number;
    };
  };
  behavior: {
    networkChangeWeight: number;
    filesystemChangeWeight: number;
    processChangeWeight: number;
    envAccessWeight: number;
    commandExecWeight: number;
  };
  runtime: {
    denyUnknownNetwork: boolean;
    denySensitiveEnv: boolean;
    denySensitiveFiles: boolean;
  };
  auth: {
    mode: "dev" | "oidc";
    defaultRole: UserIdentity["role"];
  };
}

export function defaultSentinelConfig(): SentinelConfig {
  return {
    risk: {
      thresholds: { monitor: 26, restrict: 51, approval: 76, quarantine: 91 },
      weights: { integrity: 15, behavior: 25, runtime: 20, authorization: 15, sensitivity: 10, anomaly: 15 },
      hysteresis: { margin: 5, cooldownMs: 30000 },
    },
    behavior: {
      networkChangeWeight: 30,
      filesystemChangeWeight: 25,
      processChangeWeight: 20,
      envAccessWeight: 15,
      commandExecWeight: 10,
    },
    runtime: {
      denyUnknownNetwork: true,
      denySensitiveEnv: true,
      denySensitiveFiles: true,
    },
    auth: {
      mode: "dev",
      defaultRole: "analyst",
    },
  };
}

// ── Runtime Events ──

export interface RuntimeEvent {
  type: "filesystem" | "network" | "process" | "env" | "command" | "sensitive";
  detail: string;
  timestamp: string;
  allowed: boolean;
}

// ── Sentinel Tool Call Context (extends existing ToolCallContext) ──

export interface SentinelToolContext {
  server: string;
  serverId: string;
  tool: string;
  toolId: string;
  args: unknown;
  userId: string;
  userRole: string;
  riskScore: number;
  securityState: SecurityState;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
  };
}
