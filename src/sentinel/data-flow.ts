/**
 * MCP-Sentinel: Data-Flow Guard
 * 
 * Tracks sensitive data movement across tools, resources, and external destinations.
 * Enforces taint tracking across workflow execution to prevent data exfiltration.
 * 
 * Classifications: PUBLIC | INTERNAL | CONFIDENTIAL | SECRET | CRITICAL
 * 
 * Example Violation:
 * Database -> get_credentials() [SECRET] -> send_data() [DATA_TRANSFER -> external.com]
 */

import { DataClassification, DataTaint, DataFlowCheckResult, CapabilityType } from "./types.js";

export class DataFlowGuard {
  // Workflow taints: workflowId -> DataTaint[]
  private workflowTaints: Map<string, DataTaint[]> = new Map();

  /**
   * Evaluates text and automatically classifies data sensitivity.
   */
  classifyData(text: string): DataClassification {
    const lower = text.toLowerCase();

    // Critical / Secret indicators
    if (
      lower.includes("sk-proj-") ||
      lower.includes("bearer ") ||
      lower.includes("private key") ||
      lower.includes("BEGIN RSA PRIVATE KEY") ||
      lower.includes("ghp_") ||
      lower.includes("client_secret") ||
      lower.includes("/etc/shadow") ||
      lower.includes("aws_secret_access_key")
    ) {
      return "SECRET";
    }

    // Confidential indicators
    if (
      lower.includes("confidential") ||
      lower.includes("ssn") ||
      lower.includes("credit_card") ||
      lower.includes("internal-only") ||
      lower.includes("/etc/security")
    ) {
      return "CONFIDENTIAL";
    }

    // Internal indicators
    if (lower.includes("10.") || lower.includes("192.168.") || lower.includes(".corp") || lower.includes(".internal")) {
      return "INTERNAL";
    }

    return "PUBLIC";
  }

  /**
   * Records a data taint produced by a tool execution.
   */
  recordTaint(params: {
    workflowId: string;
    originTool: string;
    originResource: string;
    outputText: string;
    overrideClassification?: DataClassification;
  }): DataTaint {
    const classification = params.overrideClassification ?? this.classifyData(params.outputText);
    const taint: DataTaint = {
      originTool: params.originTool,
      originResource: params.originResource,
      classification,
      timestamp: Date.now(),
      snippetPreview: params.outputText.slice(0, 80).replace(/[\r\n]+/g, " "),
    };

    const existing = this.workflowTaints.get(params.workflowId) ?? [];
    existing.push(taint);
    this.workflowTaints.set(params.workflowId, existing);

    return taint;
  }

  /**
   * Inspects an incoming tool call to verify if sensitive data (SECRET/CRITICAL)
   * is flowing to an unauthorized destination or external data transfer tool.
   */
  checkDataFlow(params: {
    workflowId: string;
    toolName: string;
    capability: CapabilityType;
    args: unknown;
    destination?: string;
  }): DataFlowCheckResult {
    const taints = this.workflowTaints.get(params.workflowId) ?? [];
    const secretTaints = taints.filter(
      (t) => t.classification === "SECRET" || t.classification === "CRITICAL"
    );

    // If there are no secret taints active in this workflow, allow flow
    if (secretTaints.length === 0) {
      return { allowed: true };
    }

    // Check if target tool is an external data transfer tool or contacts an external endpoint
    const isDataTransfer = params.capability === "DATA_TRANSFER" || params.toolName.toLowerCase().includes("send");
    const argsStr = JSON.stringify(params.args || "");
    const dest = params.destination || this.extractDestination(argsStr);

    if (isDataTransfer || dest) {
      const mostRecentSecret = secretTaints[secretTaints.length - 1];
      return {
        allowed: false,
        violation: {
          sourceClassification: mostRecentSecret.classification,
          targetCapability: params.capability,
          targetDestination: dest ?? "external_channel",
          reason: `Data-Flow Violation: ${mostRecentSecret.classification} data from tool "${mostRecentSecret.originTool}" (${mostRecentSecret.originResource}) is being transferred via "${params.toolName}" to external destination "${dest ?? "unknown"}"`,
        },
      };
    }

    return { allowed: true };
  }

  /**
   * Extracts external domain or URL from serialized arguments if present.
   */
  private extractDestination(text: string): string | undefined {
    const urlMatch = text.match(/https?:\/\/([a-zA-Z0-9.-]+)/);
    if (urlMatch && urlMatch[1]) {
      return urlMatch[1];
    }
    return undefined;
  }

  /**
   * Gets active taints for a workflow.
   */
  getTaints(workflowId: string): DataTaint[] {
    return this.workflowTaints.get(workflowId) ?? [];
  }
}
