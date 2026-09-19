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

    // Extract network patterns first, then blank URLs out of the text before
    // scanning for filesystem paths. The Unix-path pattern would otherwise match
    // the `//host/path` tail of every URL and report `https://evil.example/exfil`
    // as filesystem access — a wrong finding on the exact evidence an operator
    // is being asked to act on.
    for (const pattern of NETWORK_PATTERNS) {
      const matches = outputText.match(pattern) ?? [];
      for (const m of matches) {
        if (!fingerprint.network.includes(m)) {
          fingerprint.network.push(m);
        }
      }
    }

    const textWithoutUrls = outputText.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)]+/gi, " ");

    // Extract filesystem patterns
    for (const pattern of FILESYSTEM_PATTERNS) {
      const matches = textWithoutUrls.match(pattern) ?? [];
      for (const m of matches) {
        if (!fingerprint.filesystem.includes(m)) {
          fingerprint.filesystem.push(m);
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

  /**
   * Determines which observed capabilities exceed what the tool is authorized for.
   *
   * Compares semantically rather than by string equality: a private-range address
   * is not "external network", and a concrete host is only unauthorized when the
   * tool either declared no network capability at all or published an allowlist
   * this host is absent from. String comparison flagged every concrete
   * observation against every generic declaration, which made the violation
   * column meaningless.
   */
  assessConformance(
    observed: BehaviorFingerprint,
    authorized: CapabilitySet,
  ): { violations: string[]; reasons: string[] } {
    const violations: string[] = [];
    const reasons: string[] = [];

    // ── Network ──
    for (const host of observed.network) {
      if (!isExternalDestination(host)) continue;
      if (!authorized.externalNetwork) {
        violations.push(`net:${host}`);
        reasons.push(`Contacted external destination "${host}" without authorized external network capability`);
        continue;
      }
      const allowlist = authorized.network;
      if (allowlist.length > 0 && !allowlist.some((allowed) => host.includes(allowed))) {
        violations.push(`net:${host}`);
        reasons.push(`Contacted "${host}", which is outside the declared destination allowlist`);
      }
    }

    // ── Filesystem ──
    // "*" means the tool declared filesystem access without naming a scope.
    const wildcardScope = authorized.filesystem.includes("*");
    const declaredPaths = wildcardScope ? [] : authorized.filesystem;
    const declaresFilesystem = authorized.filesystem.length > 0;
    for (const path of observed.filesystem) {
      const sensitive = SENSITIVE_FILE_PATTERNS.some((p) => {
        p.lastIndex = 0;
        return p.test(path);
      });

      if (sensitive && !authorized.sensitiveFileAccess) {
        violations.push(`fs:${path}`);
        reasons.push(`Accessed sensitive path "${path}" without authorized sensitive-file capability`);
        continue;
      }
      if (!declaresFilesystem) {
        violations.push(`fs:${path}`);
        reasons.push(`Accessed "${path}" although the tool declares no filesystem capability`);
        continue;
      }
      if (declaredPaths.length > 0 && !declaredPaths.some((prefix) => path.startsWith(prefix))) {
        violations.push(`fs:${path}`);
        reasons.push(`Accessed "${path}", outside the declared filesystem scope`);
      }
    }

    // ── Boolean capabilities ──
    if (observed.envAccess && !authorized.envAccess) {
      violations.push("env_access");
      reasons.push("Read environment variables without an authorized environment capability");
    }
    if (observed.commandExecution && !authorized.commandExecution) {
      violations.push("command_execution");
      reasons.push("Executed commands without an authorized command-execution capability");
    }
    if (observed.externalNetwork && !authorized.externalNetwork) {
      violations.push("external_network");
      reasons.push("Opened an external network connection without an authorized network capability");
    }
    if (observed.sensitiveFileAccess && !authorized.sensitiveFileAccess) {
      violations.push("sensitive_files");
      reasons.push("Touched sensitive material without an authorized sensitive-file capability");
    }
    for (const proc of observed.processes) {
      if (!authorized.commandExecution) violations.push(`proc:${proc}`);
    }

    return { violations: Array.from(new Set(violations)), reasons };
  }
}

/** Private, loopback and link-local destinations are not external egress. */
function isExternalDestination(host: string): boolean {
  const value = host.toLowerCase();
  if (/localhost|127\.|0\.0\.0\.0|::1/.test(value)) return false;
  if (/(^|\/\/)10\./.test(value)) return false;
  if (/(^|\/\/)192\.168\./.test(value)) return false;
  if (/(^|\/\/)172\.(1[6-9]|2\d|3[01])\./.test(value)) return false;
  if (/(^|\/\/)169\.254\./.test(value)) return false;
  if (/\.(internal|local|corp)\b/.test(value)) return false;
  return true;
}
