/**
 * MCP-Sentinel Module Exports
 */

export { AdaptiveController } from "./adaptive-controller.js";
export type { SentinelDecision } from "./adaptive-controller.js";
export { AuthManager, ROLE_PERMISSIONS } from "./auth.js";
export type { TemporaryGrant } from "./auth.js";
export { ServerRegistry } from "./registry.js";
export { BehaviorEngine } from "./behavior.js";
export { RiskEngine } from "./risk-engine.js";
export type { RiskEvidence } from "./risk-engine.js";
export { SecurityStateMachine } from "./state-machine.js";
export type { StateTransition } from "./state-machine.js";
export { PolicyEngine } from "./policy.js";
export { RuntimeGuard } from "./runtime.js";
export { QuarantineManager } from "./quarantine.js";
export { OutputScanner } from "./output-scanner.js";
export { SentinelEventBus } from "./events.js";
export type { EventHandler } from "./events.js";
export { defaultSentinelConfig, createEmptyCapabilitySet, createEmptyFingerprint } from "./types.js";
export type {
  SentinelConfig,
  SecurityState,
  TrustStatus,
  ToolState,
  ServerRegistration,
  ToolRegistration,
  BehaviorFingerprint,
  BehaviorDriftFinding,
  DriftType,
  RiskAssessment,
  RiskFactors,
  RiskWeights,
  PolicyDecision,
  ApprovalRequest,
  QuarantineRecord,
  SecurityEvent,
  SecurityEventType,
  UserIdentity,
  SentinelToolContext,
  CapabilitySet,
  RuntimeEvent,
} from "./types.js";
