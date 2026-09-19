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
  /** Upstream-declared behavioural hints from the MCP tool descriptor. */
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
  };
  /** Findings from the Semantic Change Firewall, if this tool's contract mutated. */
  semanticChanges?: SemanticChangeFinding[];
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
    /**
     * Risk is a persistent, stateful property of an entity — not a per-call snapshot.
     * `halfLifeMs` controls how fast carried-over risk decays when behaviour is clean.
     * `accumulation` controls how much repeated bad behaviour compounds on top of
     * already-elevated risk (0 = no compounding, 1 = full additive stacking).
     */
    decay: {
      halfLifeMs: number;
      accumulation: number;
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
      decay: { halfLifeMs: 120_000, accumulation: 0.35 },
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

/**
 * Deep-merges a partial user config over the defaults.
 *
 * A shallow spread is NOT safe here: a config that supplies only
 * `risk.thresholds` (as `mcp-sentinel.json` does) would otherwise replace the
 * whole `risk` object, leaving `weights` and `hysteresis` undefined — which
 * produces NaN risk scores and throws when the state machine destructures
 * hysteresis. Every nested section falls back to its default.
 */
export function mergeSentinelConfig(partial?: DeepPartial<SentinelConfig>): SentinelConfig {
  const base = defaultSentinelConfig();
  if (!partial) return base;

  return {
    risk: {
      thresholds: { ...base.risk.thresholds, ...partial.risk?.thresholds },
      weights: { ...base.risk.weights, ...partial.risk?.weights },
      hysteresis: { ...base.risk.hysteresis, ...partial.risk?.hysteresis },
      decay: { ...base.risk.decay, ...partial.risk?.decay },
    },
    behavior: { ...base.behavior, ...partial.behavior },
    runtime: { ...base.runtime, ...partial.runtime },
    auth: { ...base.auth, ...partial.auth },
  };
}

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};

// ── Runtime Events ──

export interface RuntimeEvent {
  type: "filesystem" | "network" | "process" | "env" | "command" | "sensitive";
  detail: string;
  timestamp: string;
  allowed: boolean;
}

// ── Identity & Claims ──

export interface IdentityClaims {
  userId: string;
  agentId?: string;
  token: string;
  issuer: string;
  audience: string;
  roles: string[];
  scopes: string[];
  expiresAt: number;
}

export interface VerifiedIdentity {
  valid: boolean;
  claims?: IdentityClaims;
  error?: string;
}

// ── Capability Leases ──

export type LeaseState = "ACTIVE" | "EXPIRING" | "EXPIRED" | "REVOKED";

export interface CapabilityLease {
  leaseId: string;
  toolId: string;
  toolName: string;
  capability: string;
  scope: string;
  workflowId: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  state: LeaseState;
  revokedAt?: number;
  revocationReason?: string;
}

// ── Capability Profiles & Transition Analysis ──

export type CapabilityType = 
  | "READ"
  | "EXTERNAL_LOOKUP"
  | "WRITE"
  | "SECRET_ACCESS"
  | "DATA_TRANSFER"
  | "INFRASTRUCTURE_CONTROL"
  | "EXEC"
  | "UNKNOWN";

export interface ToolCapabilityProfile {
  toolName: string;
  primaryCapability: CapabilityType;
  riskTier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  requiresApproval: boolean;
  allowedNextCapabilities: CapabilityType[];
}

export interface CapabilityTransitionResult {
  allowed: boolean;
  fromCapability?: CapabilityType;
  toCapability: CapabilityType;
  riskIncrement: number;
  isDangerousSequence: boolean;
  reason?: string;
}

// ── Data-Flow & Sensitivity ──

export type DataClassification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "SECRET" | "CRITICAL";

export interface DataTaint {
  originTool: string;
  originResource: string;
  classification: DataClassification;
  timestamp: number;
  snippetPreview?: string;
}

export interface DataFlowCheckResult {
  allowed: boolean;
  violation?: {
    sourceClassification: DataClassification;
    targetCapability: CapabilityType;
    targetDestination?: string;
    reason: string;
  };
}

// ── Semantic Change Firewall ──

export interface SemanticChangeFinding {
  type: "CAPABILITY_EXPANSION" | "PERMISSION_EXPANSION" | "SENSITIVITY_INCREASE" | "NEW_RESOURCE_ACCESS" | "NEW_NETWORK_CAPABILITY" | "NEW_DATA_ACCESS";
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  details: {
    field: string;
    previous: unknown;
    updated: unknown;
  };
}

export interface SemanticDiffResult {
  hasSemanticChange: boolean;
  requiresRevalidation: boolean;
  findings: SemanticChangeFinding[];
  riskScoreIncrement: number;
}

// ── Workflow Context & History ──

export interface ToolCallRecord {
  toolId: string;
  toolName: string;
  server: string;
  capability: CapabilityType;
  args: unknown;
  timestamp: number;
  decision: "allow" | "block" | "require-approval";
  riskScore: number;
}

export interface WorkflowExecutionContext {
  workflowId: string;
  userId: string;
  agentId: string;
  intent: string;
  toolCallHistory: ToolCallRecord[];
  capabilityHistory: CapabilityType[];
  resourcesAccessed: Set<string>;
  dataSensitivity: DataClassification;
  activeLeases: Set<string>;
  riskScore: number;
  securityState: SecurityState;
  createdAt: number;
  updatedAt: number;
}

// ── Multi-Signal Threat Detection ──

export type ThreatType = 
  | "TOOL_POISONING"
  | "TOOL_DEFINITION_MODIFICATION"
  | "PRIVILEGE_ESCALATION"
  | "CREDENTIAL_ACCESS"
  | "DATA_EXFILTRATION"
  | "WORKFLOW_ABUSE_SEQUENCE"
  | "PROMPT_INJECTION"
  | "ABNORMAL_BEHAVIOR"
  | "UNAUTHORIZED_RESOURCE_ACCESS";

export interface ThreatSignal {
  threatType: ThreatType;
  severity: "low" | "medium" | "high" | "critical";
  source: "identity" | "integrity" | "semantic" | "context" | "transition" | "behavior" | "dataflow" | "input" | "output";
  confidence: number;
  message: string;
  evidence: unknown;
  timestamp: string;
}

// ── Verifiable Decision Receipts ──

export interface DecisionReceipt {
  receiptId: string;
  workflowId: string;
  tool: string;
  toolId: string;
  server: string;
  decision: "ALLOW" | "MONITOR" | "RESTRICT" | "REQUIRE_APPROVAL" | "QUARANTINE" | "BLOCK";
  riskScore: number;
  state: SecurityState;
  reasons: string[];
  evidence: string[];
  previousTools: string[];
  capabilityTransitions: { from?: CapabilityType; to: CapabilityType }[];
  activeLeaseId?: string;
  timestamp: string;
  hash: string;
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
  workflowId?: string;
  agentId?: string;
  intent?: string;
  authToken?: string;
  leaseId?: string;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
  };
}

