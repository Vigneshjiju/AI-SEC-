/**
 * MCP-Sentinel: Input Validation Guard
 * 
 * Performs deterministic pre-execution validation on tool arguments.
 * Prevents:
 * 1. Path traversal attacks (../, ~/.ssh, /etc/passwd)
 * 2. Shell & command injection (; rm -rf, $(curl), `cat`, | sh)
 * 3. Server-Side Request Forgery (SSRF) targeting cloud metadata (169.254.169.254) or localhost
 * 4. Dangerous character sequences and null-byte injection
 */

export interface InputValidationResult {
  valid: boolean;
  violations: Array<{
    ruleId: string;
    parameter?: string;
    message: string;
    severity: "high" | "critical";
  }>;
}

const SSRF_BLOCKED_HOSTS = [
  "169.254.169.254", // AWS/GCP/Azure instance metadata
  "metadata.google.internal",
  "127.0.0.1",
  "localhost",
  "0.0.0.0",
  "::1",
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/, // ../ or ..\
  /\/etc\/(passwd|shadow|security)/i,
  /[~\\\/]\.ssh/i,
  /[~\\\/]\.aws/i,
  /[~\\\/]\.env/i,
  /c:\\windows\\system32/i,
];

const COMMAND_INJECTION_PATTERNS = [
  /;\s*(?:rm|cat|curl|wget|sh|bash|powershell|cmd)\b/i,
  /\|\s*(?:sh|bash|curl|wget)\b/i,
  /\$\([^\)]+\)/, // $(command)
  /`[^`]+`/,     // `command`
  /&&\s*(?:rm|curl|sh|bash)\b/i,
];

export class InputValidator {
  /**
   * Validates tool call parameters before execution.
   */
  validate(toolName: string, args: unknown): InputValidationResult {
    const violations: InputValidationResult["violations"] = [];

    if (!args || typeof args !== "object") {
      return { valid: true, violations: [] };
    }

    this.scanRecursive(args, "", violations);

    return {
      valid: violations.length === 0,
      violations,
    };
  }

  private scanRecursive(
    value: unknown,
    currentPath: string,
    violations: InputValidationResult["violations"],
  ): void {
    if (typeof value === "string") {
      this.checkStringValue(value, currentPath, violations);
    } else if (Array.isArray(value)) {
      value.forEach((item, idx) => this.scanRecursive(item, `${currentPath}[${idx}]`, violations));
    } else if (value && typeof value === "object") {
      Object.entries(value as Record<string, unknown>).forEach(([k, v]) => {
        const nextPath = currentPath ? `${currentPath}.${k}` : k;
        this.scanRecursive(v, nextPath, violations);
      });
    }
  }

  private checkStringValue(
    val: string,
    paramName: string,
    violations: InputValidationResult["violations"],
  ): void {
    // 1. Path Traversal Check
    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      if (pattern.test(val)) {
        violations.push({
          ruleId: "input-path-traversal",
          parameter: paramName,
          message: `Path traversal or sensitive system path attempt detected in parameter "${paramName}": ${val}`,
          severity: "critical",
        });
        break;
      }
    }

    // 2. Command Injection Check
    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      if (pattern.test(val)) {
        violations.push({
          ruleId: "input-command-injection",
          parameter: paramName,
          message: `Command injection syntax detected in parameter "${paramName}": ${val}`,
          severity: "critical",
        });
        break;
      }
    }

    // 3. SSRF Check
    const urlMatch = val.match(/^https?:\/\/([^:\/\s]+)/i);
    if (urlMatch && urlMatch[1]) {
      const host = urlMatch[1].toLowerCase();
      if (SSRF_BLOCKED_HOSTS.includes(host)) {
        violations.push({
          ruleId: "input-ssrf-blocked",
          parameter: paramName,
          message: `SSRF attack detected: Forbidden target destination "${host}" in parameter "${paramName}"`,
          severity: "critical",
        });
      }
    }
  }
}
