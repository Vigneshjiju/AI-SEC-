/**
 * MCP-Sentinel: Behavior Fingerprint Engine
 * Creates baselines and detects behavioral drift.
 * Core detection: DECLARED capability vs AUTHORIZED vs OBSERVED.
 */

import type {
  BehaviorFingerprint,
  BehaviorDriftFinding,
  DriftType,
  CapabilitySet,
  SentinelConfig,
} from "./types.js";
import { createEmptyFingerprint } from "./types.js";

// ── Patterns for detecting behavior from tool output ──

const FILESYSTEM_PATTERNS = [
  /(?:\/[\w.-]+){2,}/g,                           // Unix paths
  /[A-Z]:\\[\w\\.-]+/g,                            // Windows paths
  /(?:read|write|open|access|stat|unlink)\s*\(/gi, // FS API calls
  /\.(env|key|pem|crt|cert|ssh|passwd|shadow)/gi,  // Sensitive file extensions
  /(?:\/etc\/|\/var\/|\/home\/|\/root\/|~\/)/g,    // System directories
];

const NETWORK_PATTERNS = [
  /https?:\/\/[^\s"'<>]+/gi,
  /wss?:\/\/[^\s"'<>]+/gi,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/g,
  /(?:fetch|axios|request|http\.get|urllib|curl|wget)\s*\(/gi,
];

const PROCESS_PATTERNS = [
  /(?:exec|spawn|fork|execFile|execSync|child_process)\s*\(/gi,
  /(?:subprocess|popen|system)\s*\(/gi,
  /\b(?:bash|sh|zsh|cmd|powershell|pwsh)\s+-c\b/gi,
];

const ENV_PATTERNS = [
  /process\.env\b/gi,
  /os\.environ\b/gi,
  /os\.getenv\s*\(/gi,
  /\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*\}?/gi,
  /(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY)\s*[=:]/gi,
];

const COMMAND_PATTERNS = [
  /\b(?:rm|sudo|curl|wget|chmod|chown|kill|shutdown|reboot|dd|mkfs)\b/gi,
  /\b(?:eval|exec)\s*\(/gi,
];

const SENSITIVE_FILE_PATTERNS = [
  /\.env\b/gi,
  /\.ssh\//gi,
  /id_rsa/gi,
  /\.aws\/credentials/gi,
  /\.kube\/config/gi,
  /\/etc\/shadow/gi,
  /\/etc\/passwd/gi,
  /\.git\/config/gi,
];

const EXTERNAL_NETWORK_INDICATORS = [
  /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/gi,
];

export class BehaviorEngine {
  private config: SentinelConfig;

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  /**
   * Create a baseline fingerprint for a tool.
   */
  createBaseline(toolId: string, custom?: Partial<BehaviorFingerprint>): BehaviorFingerprint {
    return {
      ...createEmptyFingerprint(toolId),
      ...custom,
      toolId,
    };
  }

  /**
   * Analyze tool output text to create a behavior fingerprint.
   */
  analyzeOutput(toolId: string, outputText: string, responseTimeMs: number): BehaviorFingerprint {
    const fingerprint = createEmptyFingerprint(toolId);
    fingerprint.avgResponseTimeMs = responseTimeMs;

    // Extract filesystem patterns
    for (const pattern of FILESYSTEM_PATTERNS) {
      const matches = outputText.match(pattern) ?? [];
      for (const m of matches) {
        if (!fingerprint.filesystem.includes(m)) {
          fingerprint.filesystem.push(m);
        }
      }
    }

    // Extract network patterns
    for (const pattern of NETWORK_PATTERNS) {
      const matches = outputText.match(pattern) ?? [];
      for (const m of matches) {
        if (!fingerprint.network.includes(m)) {
          fingerprint.network.push(m);
        }
      }
    }

    // Check for external network
    for (const pattern of EXTERNAL_NETWORK_INDICATORS) {
      if (pattern.test(outputText)) {
        fingerprint.externalNetwork = true;
        break;
      }
    }

    // Extract process patterns
    for (const pattern of PROCESS_PATTERNS) {
      const matches = outputText.match(pattern) ?? [];
      for (const m of matches) {
        if (!fingerprint.processes.includes(m)) {
          fingerprint.processes.push(m);
        }
      }
    }

    // Check env access
    for (const pattern of ENV_PATTERNS) {
      if (pattern.test(outputText)) {
        fingerprint.envAccess = true;
        break;
      }
    }

    // Check sensitive file access
    for (const pattern of SENSITIVE_FILE_PATTERNS) {
      if (pattern.test(outputText)) {
        fingerprint.sensitiveFileAccess = true;
        break;
      }
    }

    // Check command execution
    for (const pattern of COMMAND_PATTERNS) {
      if (pattern.test(outputText)) {
        fingerprint.commandExecution = true;
        break;
      }
    }

    // Determine data sensitivity
    if (fingerprint.sensitiveFileAccess || fingerprint.envAccess) {
      fingerprint.dataSensitivity = "high";
    } else if (fingerprint.externalNetwork || fingerprint.processes.length > 0) {
      fingerprint.dataSensitivity = "medium";
    }

    return fingerprint;
  }

  /**
   * Compare an observed fingerprint against the baseline.
   * Returns all detected drift findings.
   */
  compareFingerprint(
    baseline: BehaviorFingerprint,
    observed: BehaviorFingerprint,
    declaredCapabilities: CapabilitySet,
    authorizedCapabilities: CapabilitySet,
  ): BehaviorDriftFinding[] {
    const findings: BehaviorDriftFinding[] = [];

    // ── Filesystem drift ──
    const newFilesystem = observed.filesystem.filter(f => !baseline.filesystem.includes(f));
    if (newFilesystem.length > 0) {
      findings.push({
        type: "NEW_FILESYSTEM_ACCESS",
        severity: "high",
        message: `Tool accessed ${newFilesystem.length} previously unseen filesystem path(s)`,
        evidence: newFilesystem.join(", "),
        baselineValue: baseline.filesystem.join(", ") || "(none)",
        observedValue: observed.filesystem.join(", "),
        riskContribution: this.config.behavior.filesystemChangeWeight,
      });
    }

    // ── Network drift ──
    const newNetwork = observed.network.filter(n => !baseline.network.includes(n));
    if (newNetwork.length > 0) {
      findings.push({
        type: "NEW_EXTERNAL_NETWORK",
        severity: "high",
        message: `Tool contacted ${newNetwork.length} previously unseen network destination(s)`,
        evidence: newNetwork.join(", "),
        baselineValue: baseline.network.join(", ") || "(none)",
        observedValue: observed.network.join(", "),
        riskContribution: this.config.behavior.networkChangeWeight,
      });
    }

    // ── External network (new) ──
    if (observed.externalNetwork && !baseline.externalNetwork) {
      findings.push({
        type: "NEW_EXTERNAL_NETWORK",
        severity: "critical",
        message: "Tool initiated an external network connection not seen in baseline",
        evidence: observed.network.join(", "),
        baselineValue: "false",
        observedValue: "true",
        riskContribution: this.config.behavior.networkChangeWeight,
      });
    }

    // ── Process drift ──
    const newProcesses = observed.processes.filter(p => !baseline.processes.includes(p));
    if (newProcesses.length > 0) {
      findings.push({
        type: "NEW_PROCESS_EXECUTION",
        severity: "critical",
        message: `Tool executed ${newProcesses.length} previously unseen process(es)`,
        evidence: newProcesses.join(", "),
        baselineValue: baseline.processes.join(", ") || "(none)",
        observedValue: observed.processes.join(", "),
        riskContribution: this.config.behavior.processChangeWeight,
      });
    }

    // ── Environment access (new) ──
    if (observed.envAccess && !baseline.envAccess) {
      findings.push({
        type: "NEW_ENVIRONMENT_ACCESS",
        severity: "critical",
        message: "Tool accessed environment variables not seen in baseline",
        evidence: "Environment variable access detected in output",
        baselineValue: "false",
        observedValue: "true",
        riskContribution: this.config.behavior.envAccessWeight,
      });
    }

    // ── Sensitive file access (new) ──
    if (observed.sensitiveFileAccess && !baseline.sensitiveFileAccess) {
      findings.push({
        type: "SENSITIVE_FILE_ACCESS",
        severity: "critical",
        message: "Tool accessed sensitive files not seen in baseline",
        evidence: "Sensitive file patterns detected in output",
        baselineValue: "false",
        observedValue: "true",
        riskContribution: this.config.behavior.filesystemChangeWeight,
      });
    }

    // ── Command execution (new) ──
    if (observed.commandExecution && !baseline.commandExecution) {
      findings.push({
        type: "NEW_COMMAND_EXECUTION",
        severity: "critical",
        message: "Tool executed commands not seen in baseline",
        evidence: "Command execution patterns detected in output",
        baselineValue: "false",
        observedValue: "true",
        riskContribution: this.config.behavior.commandExecWeight,
      });
    }

    // ── Capability mismatch ──
    if (observed.externalNetwork && !authorizedCapabilities.externalNetwork) {
      findings.push({
        type: "CAPABILITY_MISMATCH",
        severity: "critical",
        message: "Observed capability exceeds authorized capability: external network access",
        evidence: "Tool has external network access but is not authorized for it",
        riskContribution: this.config.behavior.networkChangeWeight,
      });
    }

    if (observed.envAccess && !authorizedCapabilities.envAccess) {
      findings.push({
        type: "CAPABILITY_MISMATCH",
        severity: "critical",
        message: "Observed capability exceeds authorized capability: environment variable access",
        evidence: "Tool accesses environment variables but is not authorized for it",
        riskContribution: this.config.behavior.envAccessWeight,
      });
    }

    if (observed.commandExecution && !authorizedCapabilities.commandExecution) {
      findings.push({
        type: "CAPABILITY_MISMATCH",
        severity: "critical",
        message: "Observed capability exceeds authorized capability: command execution",
        evidence: "Tool executes commands but is not authorized for it",
        riskContribution: this.config.behavior.commandExecWeight,
      });
    }

    // ── General drift indicator ──
    if (findings.length > 0) {
      findings.unshift({
        type: "BEHAVIOR_DRIFT",
        severity: findings.some(f => f.severity === "critical") ? "critical" : "high",
        message: `Behavioral drift detected: ${findings.length} finding(s)`,
        evidence: findings.map(f => f.type).join(", "),
        riskContribution: 0, // Meta-finding, doesn't contribute directly
      });
    }

    return findings;
  }
}
