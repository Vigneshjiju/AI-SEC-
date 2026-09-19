/**
 * MCP-Sentinel: Shared Capability Model
 *
 * Single source of truth for "what class of thing does this tool actually do?".
 *
 * Both the RBAC layer (auth.ts) and the contextual sequence analyser
 * (contextual-engine.ts) resolve tools through this module, so a tool is never
 * classified one way for authorization and another way for sequence analysis.
 *
 * Classification is capability-based rather than an allowlist of tool names:
 * an allowlist only works for tools we have seen before, whereas MCP gateways
 * are routinely pointed at third-party servers whose tool names are unknown at
 * policy-authoring time.
 */

import type { CapabilityType, ToolCapabilityProfile, UserIdentity } from "./types.js";

// ── Known SOC / demo tools with hand-authored profiles ──

export const DEFAULT_CAPABILITY_PROFILES: Record<string, ToolCapabilityProfile> = {
  search_logs: {
    toolName: "search_logs",
    primaryCapability: "READ",
    riskTier: "LOW",
    requiresApproval: false,
    allowedNextCapabilities: ["READ", "EXTERNAL_LOOKUP", "WRITE"],
  },
  lookup_ip: {
    toolName: "lookup_ip",
    primaryCapability: "EXTERNAL_LOOKUP",
    riskTier: "LOW",
    requiresApproval: false,
    allowedNextCapabilities: ["READ", "EXTERNAL_LOOKUP", "WRITE", "INFRASTRUCTURE_CONTROL"],
  },
  create_incident: {
    toolName: "create_incident",
    primaryCapability: "WRITE",
    riskTier: "MEDIUM",
    requiresApproval: false,
    allowedNextCapabilities: ["READ", "EXTERNAL_LOOKUP", "INFRASTRUCTURE_CONTROL"],
  },
  get_credentials: {
    toolName: "get_credentials",
    primaryCapability: "SECRET_ACCESS",
    riskTier: "CRITICAL",
    requiresApproval: true,
    allowedNextCapabilities: [], // Strictly guarded — nothing may follow credential access
  },
  send_data: {
    toolName: "send_data",
    primaryCapability: "DATA_TRANSFER",
    riskTier: "HIGH",
    requiresApproval: true,
    allowedNextCapabilities: [],
  },
  block_ip: {
    toolName: "block_ip",
    primaryCapability: "INFRASTRUCTURE_CONTROL",
    riskTier: "CRITICAL",
    requiresApproval: true,
    allowedNextCapabilities: ["READ", "WRITE"],
  },
  isolate_host: {
    toolName: "isolate_host",
    primaryCapability: "INFRASTRUCTURE_CONTROL",
    riskTier: "CRITICAL",
    requiresApproval: true,
    allowedNextCapabilities: ["READ", "WRITE"],
  },
};

// ── Heuristic classifiers, evaluated in priority order ──

interface HeuristicRule {
  capability: CapabilityType;
  riskTier: ToolCapabilityProfile["riskTier"];
  requiresApproval: boolean;
  /** Matched against the tool name. */
  name: RegExp;
  /** Optional corroborating signal matched against the tool description. */
  description?: RegExp;
}

const HEURISTIC_RULES: HeuristicRule[] = [
  {
    capability: "SECRET_ACCESS",
    riskTier: "CRITICAL",
    requiresApproval: true,
    name: /(credential|secret|password|passwd|token|apikey|api_key|private_?key|keychain|vault)/i,
    description: /(credential|secret|password|private key|api key|token)/i,
  },
  {
    capability: "EXEC",
    riskTier: "CRITICAL",
    requiresApproval: true,
    name: /(^|_)(exec|execute|shell|bash|sh|spawn|cmd|command|run|eval|terminal)(_|$)/i,
    description: /(execute (a )?command|shell command|spawn (a )?process|arbitrary code)/i,
  },
  {
    capability: "INFRASTRUCTURE_CONTROL",
    riskTier: "CRITICAL",
    requiresApproval: true,
    name: /(block|isolate|quarantine|shutdown|reboot|kill|terminate|disable|revoke|contain|firewall)/i,
    description: /(firewall|isolate|disconnect|shut ?down|terminate|revoke access)/i,
  },
  {
    capability: "DATA_TRANSFER",
    riskTier: "HIGH",
    requiresApproval: true,
    name: /(send|upload|post|publish|transmit|export|exfil|push|sync_to|webhook)/i,
    description: /(send .* to|upload|external endpoint|transmit|post .* to)/i,
  },
  {
    capability: "WRITE",
    riskTier: "MEDIUM",
    requiresApproval: false,
    name: /(create|update|write|insert|add|modify|patch|set_|delete|remove|drop|purge)/i,
    description: /(create|update|write|modify|delete)/i,
  },
  {
    capability: "EXTERNAL_LOOKUP",
    riskTier: "LOW",
    requiresApproval: false,
    name: /(lookup|resolve|dns|whois|geoip|reputation|enrich|query_external)/i,
    description: /(reputation|geolocation|whois|external (lookup|service))/i,
  },
  {
    capability: "READ",
    riskTier: "LOW",
    requiresApproval: false,
    name: /(search|get|read|list|fetch|find|show|describe|scan|inspect|view)/i,
    description: /(search|retrieve|read|list|return .* entries)/i,
  },
];

/** Destructive-action name patterns, used for approval gating independent of tier. */
const DESTRUCTIVE_PATTERNS = [
  /^block_ip$/i,
  /^isolate_host$/i,
  /^delete/i,
  /^drop/i,
  /^remove/i,
  /^purge/i,
  /^shutdown/i,
  /^kill/i,
  /^terminate/i,
  /^revoke/i,
];

export function isDestructiveToolName(toolName: string): boolean {
  const clean = stripServerPrefix(toolName);
  return DESTRUCTIVE_PATTERNS.some((p) => p.test(clean));
}

export function stripServerPrefix(toolName: string): string {
  return toolName.includes("__") ? toolName.split("__").slice(1).join("__") : toolName;
}

/**
 * Resolves the capability profile for a tool.
 *
 * Resolution order: explicit profile → name heuristic (corroborated by the
 * description where available) → UNKNOWN. UNKNOWN is deliberately not treated
 * as harmless; it is gated at the analyst tier by `ROLE_CAPABILITIES`.
 */
export function classifyTool(toolName: string, description?: string): ToolCapabilityProfile {
  const cleanName = stripServerPrefix(toolName);
  const known = DEFAULT_CAPABILITY_PROFILES[cleanName.toLowerCase()];
  if (known) return known;

  const desc = description ?? "";

  // First pass: name match. A description match alone is too weak to classify on,
  // but it raises confidence enough to stop at the first matching rule.
  for (const rule of HEURISTIC_RULES) {
    if (rule.name.test(cleanName)) {
      return {
        toolName: cleanName,
        primaryCapability: rule.capability,
        riskTier: rule.riskTier,
        requiresApproval: rule.requiresApproval || isDestructiveToolName(cleanName),
        allowedNextCapabilities: defaultNextCapabilities(rule.capability),
      };
    }
  }

  // Second pass: description-only signal for tools with opaque names.
  for (const rule of HEURISTIC_RULES) {
    if (rule.description && rule.description.test(desc)) {
      return {
        toolName: cleanName,
        primaryCapability: rule.capability,
        riskTier: rule.riskTier,
        requiresApproval: rule.requiresApproval,
        allowedNextCapabilities: defaultNextCapabilities(rule.capability),
      };
    }
  }

  return {
    toolName: cleanName,
    primaryCapability: "UNKNOWN",
    riskTier: "MEDIUM",
    requiresApproval: false,
    allowedNextCapabilities: ["READ", "EXTERNAL_LOOKUP", "WRITE"],
  };
}

function defaultNextCapabilities(capability: CapabilityType): CapabilityType[] {
  switch (capability) {
    case "SECRET_ACCESS":
    case "DATA_TRANSFER":
      return [];
    case "EXEC":
      return ["READ"];
    case "INFRASTRUCTURE_CONTROL":
      return ["READ", "WRITE"];
    default:
      return ["READ", "EXTERNAL_LOOKUP", "WRITE"];
  }
}

// ── Capability-tiered RBAC ──

/**
 * Which capability classes each role may exercise.
 *
 * This is what makes authorization work against servers whose tool names were
 * never enumerated in policy: an unseen `fetch_customer_records` resolves to
 * READ and is permitted for a viewer, while an unseen `purge_bucket` resolves
 * to WRITE and is not.
 */
export const ROLE_CAPABILITIES: Record<UserIdentity["role"], CapabilityType[]> = {
  viewer: ["READ", "EXTERNAL_LOOKUP"],
  analyst: ["READ", "EXTERNAL_LOOKUP", "WRITE", "UNKNOWN"],
  incident_responder: [
    "READ",
    "EXTERNAL_LOOKUP",
    "WRITE",
    "UNKNOWN",
    "INFRASTRUCTURE_CONTROL",
    "SECRET_ACCESS",
  ],
  admin: [
    "READ",
    "EXTERNAL_LOOKUP",
    "WRITE",
    "UNKNOWN",
    "INFRASTRUCTURE_CONTROL",
    "SECRET_ACCESS",
    "DATA_TRANSFER",
    "EXEC",
  ],
};

export function roleHasCapability(role: UserIdentity["role"], capability: CapabilityType): boolean {
  return (ROLE_CAPABILITIES[role] ?? []).includes(capability);
}
