/**
 * MCP-Sentinel: Output Scanner
 * Inspects tool outputs for prompt injection, secret leakage, and suspicious patterns.
 * Defense-in-depth — does NOT claim to fully solve prompt injection.
 */

import type { SecurityFinding } from "../types/index.js";

// ── Prompt injection patterns in output ──
const OUTPUT_INJECTION_PATTERNS = [
  { pattern: /\bIMPORTANT\b.*?\b(?:ignore|override|bypass|forget|disregard)\b/i, id: "output-prompt-injection", severity: "critical" as const },
  { pattern: /\b(?:ignore|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|context|rules?)/i, id: "output-instruction-hijack", severity: "critical" as const },
  { pattern: /\byou\s+(?:are|must|should|will)\s+(?:now|actually|really)/i, id: "output-role-override", severity: "high" as const },
  { pattern: /\b(?:system|developer|admin)\s*(?:message|prompt|instruction|says)[:\s]/i, id: "output-system-impersonation", severity: "critical" as const },
  { pattern: /<!--[\s\S]*?-->/g, id: "output-hidden-html", severity: "high" as const },
  { pattern: /[\u200b\u200c\u200d\ufeff\u00ad]/, id: "output-invisible-chars", severity: "medium" as const },
];

// ── Secret leakage patterns ──
const SECRET_LEAK_PATTERNS = [
  { pattern: /(?:sk-[A-Za-z0-9]{20,})/g, id: "output-leaked-openai-key", severity: "critical" as const },
  { pattern: /(?:gh[pousr]_[A-Za-z0-9_]{20,})/g, id: "output-leaked-github-token", severity: "critical" as const },
  { pattern: /(?:xox[baprs]-[A-Za-z0-9-]{20,})/g, id: "output-leaked-slack-token", severity: "critical" as const },
  { pattern: /(?:AKIA[A-Z0-9]{16})/g, id: "output-leaked-aws-key", severity: "critical" as const },
  { pattern: /(?:eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]+)/g, id: "output-leaked-jwt", severity: "high" as const },
  { pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{8,}/gi, id: "output-leaked-password", severity: "critical" as const },
];

// ── Suspicious URL patterns ──
const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /https?:\/\/(?:evil|malicious|attacker|hack|exfil|c2)\./gi, id: "output-suspicious-url", severity: "critical" as const },
  { pattern: /https?:\/\/(?:pastebin|hastebin|webhook\.site|requestbin|ngrok)/gi, id: "output-exfil-service", severity: "high" as const },
];

// ── Suspicious command patterns ──
const SUSPICIOUS_COMMAND_PATTERNS = [
  { pattern: /\bcurl\b.*\|\s*(?:bash|sh|zsh)\b/gi, id: "output-pipe-to-shell", severity: "critical" as const },
  { pattern: /\bwget\b.*\|\s*(?:bash|sh|zsh)\b/gi, id: "output-pipe-to-shell", severity: "critical" as const },
  { pattern: /\beval\s*\(/gi, id: "output-eval-command", severity: "high" as const },
];

export class OutputScanner {
  /**
   * Scan tool output text for security concerns.
   * Returns structured findings.
   */
  scan(outputText: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const { pattern, id, severity } of OUTPUT_INJECTION_PATTERNS) {
      if (pattern.test(outputText)) {
        findings.push({
          ruleId: id,
          severity,
          message: `Tool output contains prompt injection pattern: ${id}`,
        });
      }
    }

    for (const { pattern, id, severity } of SECRET_LEAK_PATTERNS) {
      if (pattern.test(outputText)) {
        findings.push({
          ruleId: id,
          severity,
          message: `Tool output may contain leaked secrets: ${id}`,
        });
      }
    }

    for (const { pattern, id, severity } of SUSPICIOUS_URL_PATTERNS) {
      if (pattern.test(outputText)) {
        findings.push({
          ruleId: id,
          severity,
          message: `Tool output contains suspicious URL: ${id}`,
        });
      }
    }

    for (const { pattern, id, severity } of SUSPICIOUS_COMMAND_PATTERNS) {
      if (pattern.test(outputText)) {
        findings.push({
          ruleId: id,
          severity,
          message: `Tool output contains suspicious command pattern: ${id}`,
        });
      }
    }

    return findings;
  }
}
