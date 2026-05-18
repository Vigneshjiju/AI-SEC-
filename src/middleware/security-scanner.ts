import type { Middleware, ToolCallContext, MiddlewareResult, SecurityPolicy, SecurityFinding, GatewayConfig } from "../types/index.js";

const POISONING_PATTERNS = [
  // --- Original 7 ---
  { pattern: /\bIMPORTANT\b.*?\b(ignore|override|bypass|forget|disregard)\b/i, id: "poison-override" },
  { pattern: /\b(do not|don't|never)\s+(tell|inform|reveal|show|display|mention)\s+(the\s+)?(user|human)/i, id: "poison-conceal" },
  { pattern: /\b(instead|actually|secretly|silently|quietly)\s+(send|transmit|exfiltrate|upload|post|forward)/i, id: "poison-exfil" },
  { pattern: /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|rules?)/i, id: "poison-hijack" },
  { pattern: /\byou\s+(are|must|should|will)\s+(now|actually|really)/i, id: "poison-role" },
  { pattern: /<!--[\s\S]*?-->/g, id: "poison-hidden-html" },
  { pattern: /\u200b|\u200c|\u200d|\ufeff|\u00ad/g, id: "poison-invisible" },

  // --- New: URL exfiltration ---
  { pattern: /\b(https?|wss?):\/\/[^\s"'`<>\])}]+/gi, id: "poison-url-exfil" },

  // --- New: Data URI abuse ---
  { pattern: /data:(text\/html|application\/(?:javascript|x-javascript|ecmascript))[;,]/gi, id: "poison-data-uri" },

  // --- New: Environment variable leaking ---
  { pattern: /\b(process\.env|os\.environ|os\.getenv)\b/i, id: "poison-env-leak" },
  { pattern: /\b(ENV|HOME|PATH|USER|SHELL|SECRET|TOKEN|API_KEY|PASSWORD|CREDENTIAL)\b/, id: "poison-env-var-ref" },

  // --- New: Tool name squatting ---
  { pattern: /\b(rm|sudo|curl|wget|eval|exec|chmod|chown|kill|shutdown|reboot|mkfs|dd)\b/i, id: "poison-tool-squat" },

  // --- New: Descriptor mimicry ---
  { pattern: /\b(this is (?:an? )?(?:official|system|built-?in|core|internal|default) (?:tool|command|utility|function))\b/i, id: "poison-mimicry" },
  { pattern: /\b(you (?:must|should|shall) (?:always|only) (?:use|call|invoke) this (?:tool|server|service))\b/i, id: "poison-mimicry-mandatory" },

  // --- New: Recursive self-reference ---
  { pattern: /\b(call|invoke|execute|run)\s+(this|itself|self)\b/i, id: "poison-self-ref" },
  { pattern: /\b(recursive|loop|repeat|iterate)\s+(this|until|while|forever)\b/i, id: "poison-recursive" },

  // --- New: Model confusion ---
  { pattern: /\b(system|developer|admin)\s*(message|prompt|instruction|says)[:\s]/i, id: "poison-model-confusion" },
  { pattern: /\b(I am|I'm) (?:the )?(system|developer|admin|creator|OpenAI|Anthropic|assistant)\b/i, id: "poison-model-confusion-identity" },

  // --- New: Token/credential harvesting ---
  { pattern: /\b(send|share|provide|return|output|expose|leak|transmit)\s+(?:your\s+)?(API\s*key|token|password|secret|credential|auth)\b/i, id: "poison-cred-harvest" },
  { pattern: /\b(what is|tell me|give me|show me)\s+(?:your\s+)?(API\s*key|token|password|secret|credential|auth)\b/i, id: "poison-cred-harvest-ask" },

  // --- New: Network exfiltration ---
  { pattern: /\b(fetch|axios|request|http\.get|urllib|requests\.(?:get|post|put))\s*\(\s*['"`]/i, id: "poison-net-exfil" },
  { pattern: /\b(webhook|endpoint|callback)\s*(url|uri)[:=]/i, id: "poison-net-exfil-endpoint" },

  // --- New: Prompt leaking ---
  { pattern: /\b(repeat|show|display|print|output|reveal|dump|expose)\s+(your\s+)?(system\s*prompt|instructions?|rules?|context)\b/i, id: "poison-prompt-leak" },
  { pattern: /\b(what (?:are|is) your (?:system\s+)?(?:prompt|instructions?|rules?|guidelines?))\b/i, id: "poison-prompt-leak-ask" },
];

const INJECTION_PATTERNS = [
  // --- Original 3 ---
  { pattern: /[;&|`$]/, id: "input-shell-chars", severity: "high" as const },
  { pattern: /\.\.[\/\\]/, id: "input-path-traversal", severity: "high" as const },
  { pattern: /<script/i, id: "input-xss", severity: "medium" as const },

  // --- New: Command substitution ---
  { pattern: /\$\([^)]*\)/, id: "input-cmd-subst-paren", severity: "high" as const },
  { pattern: /`[^`]+`/, id: "input-cmd-subst-backtick", severity: "high" as const },

  // --- New: Newline injection ---
  { pattern: /\\[rn]|[\x0a\x0d]/, id: "input-newline-inject", severity: "medium" as const },

  // --- New: Null byte injection ---
  { pattern: /\\x00|%00|\x00/, id: "input-null-byte", severity: "critical" as const },

  // --- New: Unicode normalization / homoglyphs ---
  // Matches common homoglyph substitutions (Cyrillic lookalikes, etc.)
  { pattern: /[\u0410-\u044f\u0401\u0451]/, id: "input-homoglyph", severity: "medium" as const },

  // --- New: Format string attacks ---
  { pattern: /%[0-9]*[sdxpfn]/, id: "input-format-string", severity: "medium" as const },

  // --- New: SSRF patterns ---
  { pattern: /\b(file|gopher|dict|ftp|ldap):\/\//i, id: "input-ssrf", severity: "high" as const },
];

/** Shell interpreters that are dangerous when invoked with -c */
const SHELL_INTERPRETERS = new Set([
  "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
  "cmd", "cmd.exe", "powershell", "pwsh", "powershell.exe",
]);

/** Protocols considered insecure or deprecated */
const INSECURE_TRANSPORTS = [
  /^http:\/\//i,  // not HTTPS
  /^ws:\/\//i,    // not WSS
];

/** Patterns that look like plaintext secrets in env values */
const SECRET_PATTERNS = [
  /^[A-Za-z0-9+/=_-]{20,}$/,               // long base64-ish tokens
  /^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}$/, // GitHub tokens
  /^sk-[A-Za-z0-9]{20,}$/,                  // OpenAI / Stripe style keys
  /^xox[bpsar]-[A-Za-z0-9-]+$/,             // Slack tokens
  /^AKIA[A-Z0-9]{16}$/,                     // AWS access key
  /^[A-Za-z0-9]{32,}$/,                     // generic long hex/base64
];

/**
 * Scan an MCP server configuration for security issues.
 * Validates commands, environment variables, URLs, and transports.
 */
export function scanMcpServerConfig(config: unknown): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  if (!config || typeof config !== "object") {
    findings.push({
      ruleId: "config-invalid",
      severity: "medium",
      message: "Server configuration is not a valid object",
    });
    return findings;
  }

  const gatewayConfig = config as GatewayConfig;
  const servers = gatewayConfig.servers;

  if (!servers || typeof servers !== "object") {
    findings.push({
      ruleId: "config-no-servers",
      severity: "low",
      message: "No servers defined in configuration",
    });
    return findings;
  }

  for (const [name, serverConfig] of Object.entries(servers)) {
    if (!serverConfig || typeof serverConfig !== "object") {
      findings.push({
        ruleId: "config-server-invalid",
        severity: "medium",
        message: `Server "${name}" has invalid configuration`,
      });
      continue;
    }

    const { command, args, env, url } = serverConfig;

    // --- Check for shell interpreters with -c flags ---
    if (typeof command === "string") {
      const cmdBase = command.split(/[/\\]/).pop() ?? command;
      if (SHELL_INTERPRETERS.has(cmdBase)) {
        const hasDashC = Array.isArray(args) && args.includes("-c");
        if (hasDashC) {
          findings.push({
            ruleId: "config-shell-interpreter",
            severity: "critical",
            message: `Server "${name}" uses shell interpreter "${command}" with -c flag — high risk of command injection`,
          });
        } else {
          findings.push({
            ruleId: "config-shell-interpreter-warn",
            severity: "medium",
            message: `Server "${name}" uses shell interpreter "${command}" — ensure args are trusted`,
          });
        }
      }
    }

    // --- Check environment variables for obvious secrets in plaintext ---
    if (env && typeof env === "object") {
      for (const [envKey, envValue] of Object.entries(env)) {
        if (typeof envValue !== "string") continue;

        const keyLower = envKey.toLowerCase();
        const isSecretKey = /\b(secret|token|key|password|passwd|credential|auth|apikey|api_key)\b/i.test(envKey);

        if (isSecretKey) {
          // If the value looks like a literal secret (not an env var reference)
          if (!envValue.startsWith("$") && !envValue.startsWith("%") && !envValue.startsWith("{{")) {
            findings.push({
              ruleId: "config-plaintext-secret",
              severity: "high",
              message: `Server "${name}" has environment variable "${envKey}" that appears to contain a plaintext secret`,
            });
          }
        }

        // Also check if any value matches known secret patterns regardless of key name
        for (const secretPattern of SECRET_PATTERNS) {
          if (secretPattern.test(envValue) && isSecretKey) {
            findings.push({
              ruleId: "config-secret-pattern",
              severity: "high",
              message: `Server "${name}" environment variable "${envKey}" value matches a known secret pattern`,
            });
            break;
          }
        }
      }
    }

    // --- Check URLs for localhost / 127.0.0.1 ---
    if (typeof url === "string" && url.length > 0) {
      try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "0.0.0.0";

        if (isLocalhost) {
          findings.push({
            ruleId: "config-localhost-url",
            severity: "medium",
            message: `Server "${name}" URL "${url}" targets localhost — ensure this is intentional for local-only servers`,
          });
        }

        // --- Check for insecure transports ---
        for (const transportPattern of INSECURE_TRANSPORTS) {
          if (transportPattern.test(url)) {
            findings.push({
              ruleId: "config-insecure-transport",
              severity: "high",
              message: `Server "${name}" uses insecure transport "${url}" — prefer HTTPS/WSS`,
            });
            break;
          }
        }
      } catch {
        findings.push({
          ruleId: "config-invalid-url",
          severity: "medium",
          message: `Server "${name}" has invalid URL "${url}"`,
        });
      }
    }
  }

  return findings;
}

export function createSecurityScanner(policy: SecurityPolicy): Middleware {
  return (ctx: ToolCallContext): MiddlewareResult => {
    const findings: SecurityFinding[] = [];

    if (policy.scanInputs && ctx.args) {
      const inputStr = JSON.stringify(ctx.args);
      for (const { pattern, id, severity } of INJECTION_PATTERNS) {
        if (pattern.test(inputStr)) {
          findings.push({
            ruleId: id,
            severity,
            message: `Suspicious characters in tool input for ${ctx.tool}`,
          });
        }
      }
    }

    const hasCritical = findings.some(f => f.severity === "critical");
    const hasHigh = findings.some(f => f.severity === "high");

    if (hasCritical && policy.blockOnCritical) {
      return { action: "block", reason: "Critical security finding in tool call", findings };
    }

    if (hasHigh && policy.blockOnHigh) {
      return { action: "block", reason: "High severity security finding in tool call", findings };
    }

    return { action: "allow", findings: findings.length > 0 ? findings : undefined };
  };
}

export function scanToolDescription(description: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const { pattern, id } of POISONING_PATTERNS) {
    if (pattern.test(description)) {
      findings.push({
        ruleId: id,
        severity: "critical",
        message: `Tool description contains suspicious pattern: ${id}`,
      });
    }
  }

  return findings;
}
