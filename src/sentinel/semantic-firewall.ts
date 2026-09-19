/**
 * MCP-Sentinel: Semantic Change Firewall
 * 
 * Compares the semantic meaning and capability profile of an updated tool definition
 * with its previously trusted baseline.
 * 
 * Goes beyond simple binary/cryptographic hash checks to detect:
 * 1. Capability expansion (e.g. tool quietly adding environment or network access)
 * 2. Permission & parameter expansion (new parameters like command, url, path)
 * 3. Sensitivity elevation
 * 4. New resource or network access patterns
 */

import { SemanticDiffResult, SemanticChangeFinding, ToolRegistration } from "./types.js";

interface SemanticCategoryKeywords {
  category: "env" | "network" | "filesystem" | "process" | "credentials";
  findingType: SemanticChangeFinding["type"];
  severity: SemanticChangeFinding["severity"];
  keywords: string[];
}

const SEMANTIC_CATEGORIES: SemanticCategoryKeywords[] = [
  {
    category: "credentials",
    findingType: "NEW_DATA_ACCESS",
    severity: "critical",
    keywords: ["credential", "password", "secret", "private key", "api_key", "token", "auth token", "id_rsa", "keychain"],
  },
  {
    category: "env",
    findingType: "CAPABILITY_EXPANSION",
    severity: "high",
    keywords: ["environment", "process.env", "env variable", "environment configuration", "env vars", "system configuration"],
  },
  {
    category: "process",
    findingType: "PERMISSION_EXPANSION",
    severity: "critical",
    keywords: ["exec", "execute command", "spawn", "shell", "bash", "cmd.exe", "system command", "run process", "subprocess"],
  },
  {
    category: "network",
    findingType: "NEW_NETWORK_CAPABILITY",
    severity: "high",
    keywords: ["outbound", "external network", "http request", "upload", "download", "send data", "webhook", "telemetry to", "c2"],
  },
  {
    category: "filesystem",
    findingType: "NEW_RESOURCE_ACCESS",
    severity: "high",
    keywords: ["file system", "read file", "write file", "arbitrary path", "/etc/", "/root", "~/.ssh", "~/.aws", "delete file"],
  },
];

export class SemanticChangeFirewall {
  /**
   * Compares the previous trusted tool definition against an incoming updated definition.
   */
  evaluateUpdate(
    previous: ToolRegistration,
    updated: {
      description?: string;
      inputSchema?: Record<string, unknown>;
      sensitivity?: "public" | "internal" | "confidential" | "restricted";
      criticality?: "low" | "medium" | "high" | "critical";
      declaredCapabilities?: {
        filesystem?: string[];
        network?: string[];
        processes?: string[];
        envAccess?: boolean;
        externalNetwork?: boolean;
        commandExecution?: boolean;
      };
    },
  ): SemanticDiffResult {
    const findings: SemanticChangeFinding[] = [];
    let riskScoreIncrement = 0;

    const prevDesc = (previous.description || "").toLowerCase();
    const newDesc = (updated.description || "").toLowerCase();

    // ── 1. Semantic Analysis of Description Evolution ──
    if (updated.description && newDesc !== prevDesc) {
      for (const cat of SEMANTIC_CATEGORIES) {
        const prevHasCat = cat.keywords.some((k) => prevDesc.includes(k));
        const newKeywords = cat.keywords.filter((k) => newDesc.includes(k) && !prevDesc.includes(k));

        if (!prevHasCat && newKeywords.length > 0) {
          findings.push({
            type: cat.findingType,
            severity: cat.severity,
            description: `Tool description expanded to include semantic capability "${cat.category}" (triggers: ${newKeywords.slice(0, 3).join(", ")})`,
            details: {
              field: "description",
              previous: previous.description,
              updated: updated.description,
            },
          });
          riskScoreIncrement += cat.severity === "critical" ? 35 : 20;
        }
      }
    }

    // ── 2. Parameter & Schema Expansion ──
    if (updated.inputSchema && typeof updated.inputSchema === "object") {
      const prevSchema = (previous.inputSchema as Record<string, unknown>) || {};
      const prevProps = ((prevSchema.properties as Record<string, unknown>) || {});
      const newProps = ((updated.inputSchema.properties as Record<string, unknown>) || {});

      const prevPropKeys = new Set(Object.keys(prevProps));
      const newPropKeys = Object.keys(newProps);

      const suspiciousParamNames = ["cmd", "command", "exec", "url", "uri", "endpoint", "dest", "path", "filePath", "env", "token"];

      for (const key of newPropKeys) {
        if (!prevPropKeys.has(key)) {
          const isSuspicious = suspiciousParamNames.some((sp) => key.toLowerCase().includes(sp));
          findings.push({
            type: "PERMISSION_EXPANSION",
            severity: isSuspicious ? "high" : "medium",
            description: `Tool input schema added new parameter "${key}"${isSuspicious ? " (sensitive parameter name detected)" : ""}`,
            details: {
              field: `inputSchema.properties.${key}`,
              previous: undefined,
              updated: newProps[key],
            },
          });
          riskScoreIncrement += isSuspicious ? 25 : 10;
        }
      }
    }

    // ── 3. Sensitivity Elevation ──
    const sensitivityRank: Record<string, number> = {
      public: 1,
      internal: 2,
      confidential: 3,
      restricted: 4,
    };

    if (updated.sensitivity && updated.sensitivity !== previous.sensitivity) {
      const prevRank = sensitivityRank[previous.sensitivity] || 1;
      const newRank = sensitivityRank[updated.sensitivity] || 1;
      if (newRank > prevRank) {
        findings.push({
          type: "SENSITIVITY_INCREASE",
          severity: "high",
          description: `Tool sensitivity rating elevated from ${previous.sensitivity.toUpperCase()} to ${updated.sensitivity.toUpperCase()}`,
          details: {
            field: "sensitivity",
            previous: previous.sensitivity,
            updated: updated.sensitivity,
          },
        });
        riskScoreIncrement += 20;
      }
    }

    // ── 4. Declared Capabilities Expansion ──
    if (updated.declaredCapabilities) {
      const prevCaps = previous.declaredCapabilities;
      const newCaps = updated.declaredCapabilities;

      if (!prevCaps.envAccess && newCaps.envAccess) {
        findings.push({
          type: "CAPABILITY_EXPANSION",
          severity: "high",
          description: "Tool declared new environment variable access capability",
          details: { field: "declaredCapabilities.envAccess", previous: false, updated: true },
        });
        riskScoreIncrement += 25;
      }

      if (!prevCaps.commandExecution && newCaps.commandExecution) {
        findings.push({
          type: "PERMISSION_EXPANSION",
          severity: "critical",
          description: "Tool declared new command execution capability",
          details: { field: "declaredCapabilities.commandExecution", previous: false, updated: true },
        });
        riskScoreIncrement += 40;
      }

      if (!prevCaps.externalNetwork && newCaps.externalNetwork) {
        findings.push({
          type: "NEW_NETWORK_CAPABILITY",
          severity: "high",
          description: "Tool declared new external network communication capability",
          details: { field: "declaredCapabilities.externalNetwork", previous: false, updated: true },
        });
        riskScoreIncrement += 30;
      }
    }

    const hasSemanticChange = findings.length > 0;
    const requiresRevalidation = findings.some(
      (f) => f.severity === "high" || f.severity === "critical"
    );

    return {
      hasSemanticChange,
      requiresRevalidation,
      findings,
      riskScoreIncrement: Math.min(100, riskScoreIncrement),
    };
  }
}
