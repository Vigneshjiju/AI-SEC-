/**
 * MCP-Sentinel: Runtime Capability Guard
 * Monitors and controls capabilities used by a tool at runtime.
 * Inspects tool outputs for behavioral signals.
 */

import type {
  RuntimeEvent,
  SentinelConfig,
  CapabilitySet,
} from "./types.js";

// ── Sensitive file patterns ──
const SENSITIVE_FILES = [
  /\.env\b/i,
  /\.ssh\//i,
  /id_rsa/i,
  /\.aws\/credentials/i,
  /\.kube\/config/i,
  /\/etc\/shadow/i,
  /\/etc\/passwd/i,
  /\.git\/config/i,
  /\.npmrc/i,
  /\.docker\/config/i,
  /private[_-]?key/i,
];

// ── Suspicious network destinations ──
const SUSPICIOUS_DOMAINS = [
  /evil\./i,
  /malicious\./i,
  /attacker\./i,
  /hack\./i,
  /exfil/i,
  /c2\./i,
  /pastebin\./i,
  /ngrok\.io/i,
  /webhook\.site/i,
  /requestbin/i,
];

// ── Dangerous commands ──
const DANGEROUS_COMMANDS = [
  /\brm\s+-rf\b/i,
  /\bsudo\b/i,
  /\bcurl\b.*\|.*\bsh\b/i,
  /\bwget\b.*\|.*\bsh\b/i,
  /\bchmod\s+[0-7]*7[0-7]*/i,
  /\bdd\s+if=/i,
  /\bmkfs\b/i,
  /\bshutdown\b/i,
  /\breboot\b/i,
];

export class RuntimeGuard {
  private config: SentinelConfig;
  private eventLog: RuntimeEvent[] = [];

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  /**
   * Inspect tool output and generate runtime events.
   * Returns events that indicate capability usage.
   */
  inspectOutput(
    outputText: string,
    authorizedCapabilities: CapabilitySet,
  ): RuntimeEvent[] {
    const events: RuntimeEvent[] = [];
    const now = new Date().toISOString();

    // ── Filesystem monitoring ──
    for (const pattern of SENSITIVE_FILES) {
      if (pattern.test(outputText)) {
        const allowed = !this.config.runtime.denySensitiveFiles;
        events.push({
          type: "sensitive",
          detail: `Sensitive file access detected: ${pattern.source}`,
          timestamp: now,
          allowed,
        });
      }
    }

    // ── Network monitoring ──
    const urls = outputText.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
    for (const url of urls) {
      const isSuspicious = SUSPICIOUS_DOMAINS.some(p => p.test(url));
      const isExternal = !/localhost|127\.0\.0\.1|0\.0\.0\.0|::1/.test(url);

      if (isSuspicious) {
        events.push({
          type: "network",
          detail: `Suspicious network destination detected: ${url}`,
          timestamp: now,
          allowed: false,
        });
      } else if (isExternal && this.config.runtime.denyUnknownNetwork && !authorizedCapabilities.externalNetwork) {
        events.push({
          type: "network",
          detail: `External network access detected (not authorized): ${url}`,
          timestamp: now,
          allowed: false,
        });
      }
    }

    // ── Environment variable monitoring ──
    const envPatterns = [
      /process\.env\.\w+/gi,
      /os\.environ\[/gi,
      /\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*\}?/gi,
    ];
    for (const pattern of envPatterns) {
      if (pattern.test(outputText)) {
        const allowed = !this.config.runtime.denySensitiveEnv;
        events.push({
          type: "env",
          detail: `Environment variable access detected: ${pattern.source}`,
          timestamp: now,
          allowed,
        });
        break;
      }
    }

    // ── Command execution monitoring ──
    for (const pattern of DANGEROUS_COMMANDS) {
      if (pattern.test(outputText)) {
        events.push({
          type: "command",
          detail: `Dangerous command detected: ${pattern.source}`,
          timestamp: now,
          allowed: false,
        });
      }
    }

    // ── Process execution monitoring ──
    const processPatterns = [
      /(?:exec|spawn|fork|execFile|execSync)\s*\(/gi,
      /child_process/gi,
      /subprocess|popen|system\(/gi,
    ];
    for (const pattern of processPatterns) {
      if (pattern.test(outputText)) {
        events.push({
          type: "process",
          detail: `Process execution pattern detected: ${pattern.source}`,
          timestamp: now,
          allowed: authorizedCapabilities.commandExecution,
        });
        break;
      }
    }

    // Store events
    for (const event of events) {
      this.eventLog.push(event);
    }
    if (this.eventLog.length > 10000) {
      this.eventLog = this.eventLog.slice(-10000);
    }

    return events;
  }

  /**
   * Check if any blocking events were generated.
   */
  hasBlockingEvents(events: RuntimeEvent[]): boolean {
    return events.some(e => !e.allowed);
  }

  /**
   * Get recent runtime events.
   */
  getEvents(limit = 100): RuntimeEvent[] {
    return this.eventLog.slice(-limit);
  }
}
