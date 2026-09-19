#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { homedir } from "node:os";
import { existsSync, readdirSync } from "node:fs";
import { Command } from "commander";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { McpGateway } from "./proxy/gateway.js";
import { startDashboard } from "./dashboard/server.js";
import { createRunReport, markdownReportRenderer } from "./reporting/report.js";
import { scanToolDescription } from "./middleware/security-scanner.js";
import type { GatewayConfig, SecurityFinding } from "./types/index.js";

const program = new Command();

program
  .name("mcp-gateway")
  .description("Security-first gateway proxy for MCP servers with MCP-Sentinel control plane")
  .version("0.2.0");

program
  .command("start")
  .description("Start the gateway proxy with optional Sentinel control plane and dashboard")
  .option("-c, --config <path>", "Path to gateway config file", "mcp-gateway.json")
  .option("-s, --sentinel <path>", "Path to Sentinel config file (auto-detects sentinel.config.json)")
  .option("-d, --dashboard", "Start the security dashboard alongside the gateway")
  .option("-p, --port <port>", "Dashboard port", "3100")
  .option("-v, --verbose", "Enable verbose debug logging")
  .action(async (opts) => {
    try {
      const configPath = resolve(opts.config);
      const raw = await readFile(configPath, "utf-8");
      let config: GatewayConfig;
      try {
        config = JSON.parse(raw);
      } catch {
        process.stderr.write(`Error: Invalid JSON in ${configPath}\n`);
        process.exit(1);
      }

      if (!config.servers || Object.keys(config.servers).length === 0) {
        process.stderr.write(`Error: No servers defined in config\n`);
        process.exit(1);
      }

      for (const [name, srv] of Object.entries(config.servers)) {
        if (!srv.command && !srv.url) {
          process.stderr.write(`Error: Server "${name}" needs either command or url\n`);
          process.exit(1);
        }
      }

      // Check for Sentinel configuration
      let sentinelConfig: any = undefined;
      const sentinelPath = opts.sentinel ? resolve(opts.sentinel) : resolve("sentinel.config.json");
      if (existsSync(sentinelPath)) {
        try {
          const sRaw = await readFile(sentinelPath, "utf-8");
          sentinelConfig = JSON.parse(sRaw);
          if (opts.verbose) {
            process.stderr.write(`[sentinel] Loaded config from ${sentinelPath}\n`);
          }
        } catch {
          // ignore or fallback
        }
      }
      if (!sentinelConfig && (config as any).sentinel) {
        sentinelConfig = (config as any).sentinel;
      }

      if (opts.verbose) {
        process.stderr.write(`[mcp-gateway] Config: ${Object.keys(config.servers).length} servers\n`);
        process.stderr.write(`[mcp-gateway] Policies: rate=${!!config.policies?.rateLimit} security=${!!config.policies?.security} approval=${!!config.policies?.approval}\n`);
        process.stderr.write(`[mcp-gateway] Audit: ${config.audit?.enabled ? config.audit.logPath : "disabled"}\n`);
        process.stderr.write(`[mcp-gateway] Sentinel: ${sentinelConfig ? "enabled" : "disabled"}\n`);
      }

      const gateway = new McpGateway(config, sentinelConfig);

      if (opts.dashboard) {
        const auditLogPath = resolve(config.audit?.logPath ?? "./mcp-gateway-audit.jsonl");
        const serverNames = Object.keys(config.servers);
        const limit = config.policies?.rateLimit?.maxCallsPerMinute ?? 30;

        await startDashboard({
          port: parseInt(opts.port || "3100", 10),
          auditLogPath,
          getStatus: () => ({
            servers: serverNames.map((name) => ({ name, tools: 0 })),
            rateLimits: Object.entries(config.policies?.rateLimit?.perTool ?? {}).map(
              ([tool, conf]) => ({
                tool,
                count: 0,
                limit: (conf as { maxCallsPerMinute: number }).maxCallsPerMinute ?? limit,
              })
            ),
          }),
          getSentinel: () => gateway.getSentinel(),
        });
      }

      process.on("SIGINT", async () => {
        process.stderr.write("\n[mcp-gateway] Shutting down...\n");
        await gateway.stop();
        process.exit(0);
      });

      process.on("SIGTERM", async () => {
        await gateway.stop();
        process.exit(0);
      });

      await gateway.start();
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
  });

program
  .command("init")
  .description("Generate a sample gateway configuration with security scanning enabled")
  .option("--legacy", "Generate legacy config without security defaults")
  .action((opts) => {
    const sample: GatewayConfig = {
      servers: {
        filesystem: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem", "./project"],
        },
        github: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-github"],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" },
        },
      },
      policies: {
        rateLimit: {
          maxCallsPerMinute: 30,
          maxCallsPerHour: 500,
          perTool: {
            write_file: { maxCallsPerMinute: 5 },
            delete_file: { maxCallsPerMinute: 2 },
          },
        },
        approval: {
          requireApprovalFor: [
            { type: "destructive" },
            { type: "pattern", match: "delete|drop|remove|push" },
          ],
          approvalTimeout: 30000,
          defaultAction: "deny",
        },
        security: {
          blockOnCritical: true,
          blockOnHigh: true,
          scanDescriptions: true,
          scanInputs: true,
          descriptorBaselinePath: "./.mcp-gateway-descriptors.json",
          descriptorChangeAction: "warn",
        },
      },
      audit: {
        enabled: true,
        logPath: "./mcp-audit.jsonl",
        includeArgs: true,
        includeResults: false,
      },
    };

    if (opts.legacy) {
      // Legacy: weaker defaults for backwards compat
      (sample.policies!.security as { blockOnHigh: boolean }).blockOnHigh = false;
    }

    const initComment = [
      "// MCP Gateway Configuration",
      "// Generated by mcp-gateway init",
      "// Security scanning is enabled by default.",
      "// Run 'mcp-gateway scan' to audit your MCP server configurations.",
      "",
    ].join("\n");

    process.stdout.write(initComment + JSON.stringify(sample, null, 2) + "\n");
  });

program
  .command("validate")
  .description("Validate a gateway configuration file")
  .argument("<config-path>", "Path to gateway config")
  .action(async (configPath: string) => {
    try {
      const raw = await readFile(resolve(configPath), "utf-8");
      const config: GatewayConfig = JSON.parse(raw);

      const serverCount = Object.keys(config.servers).length;
      const hasRateLimit = !!config.policies?.rateLimit;
      const hasApproval = !!config.policies?.approval;
      const hasSecurity = !!config.policies?.security;
      const hasAudit = !!config.audit?.enabled;

      console.log(`\n  Configuration Valid\n`);
      console.log(`  Servers:       ${serverCount}`);
      console.log(`  Rate Limiting: ${hasRateLimit ? "enabled" : "disabled"}`);
      console.log(`  Approval Gate: ${hasApproval ? "enabled" : "disabled"}`);
      console.log(`  Security Scan: ${hasSecurity ? "enabled" : "disabled"}`);
      console.log(`  Audit Log:     ${hasAudit ? "enabled" : "disabled"}`);
      console.log();
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Invalid config: ${msg}\n`);
      process.exit(1);
    }
  });

program
  .command("report")
  .description("Generate a local run report from MCP Gateway audit logs")
  .requiredOption("--audit <path>", "Path to MCP Gateway audit JSONL")
  .option("-c, --config <path>", "Path to gateway config file")
  .option("--baseline <path>", "Path to descriptor baseline JSON")
  .option("--diff <path>", "Path to a git diff/patch file for the run")
  .option("--metadata <path>", "Path to run metadata JSON")
  .option("--out <path>", "Write Markdown report to this path instead of stdout")
  .option("--json <path>", "Write JSON report summary to this path")
  .option("--public", "Redact secrets and generate a share-safe report")
  .action(async (opts) => {
    try {
      const report = await createRunReport({
        auditPath: resolve(opts.audit),
        configPath: opts.config ? resolve(opts.config) : undefined,
        baselinePath: opts.baseline ? resolve(opts.baseline) : undefined,
        diffPath: opts.diff ? resolve(opts.diff) : undefined,
        metadataPath: opts.metadata ? resolve(opts.metadata) : undefined,
        publicMode: !!opts.public,
      });

      const markdown = markdownReportRenderer.renderMarkdown(report);
      if (opts.out) {
        await writeFile(resolve(opts.out), markdown);
      } else {
        process.stdout.write(markdown);
      }

      if (opts.json) {
        await writeFile(resolve(opts.json), markdownReportRenderer.renderJson(report));
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
  });

program
  .command("dashboard")
  .description("Start the monitoring dashboard")
  .option("-c, --config <path>", "Path to gateway config file", "mcp-gateway.json")
  .option("-p, --port <port>", "Dashboard port", "3100")
  .action(async (opts) => {
    try {
      const configPath = resolve(opts.config);
      const raw = await readFile(configPath, "utf-8");
      const config: GatewayConfig = JSON.parse(raw);

      const auditLogPath = resolve(config.audit?.logPath ?? "./mcp-gateway-audit.jsonl");
      const serverNames = Object.keys(config.servers);
      const limit = config.policies?.rateLimit?.maxCallsPerMinute ?? 30;

      await startDashboard({
        port: parseInt(opts.port, 10),
        auditLogPath,
        getStatus: () => ({
          servers: serverNames.map(name => ({ name, tools: 0 })),
          rateLimits: Object.entries(config.policies?.rateLimit?.perTool ?? {}).map(
            ([tool, conf]) => ({ tool, count: 0, limit: (conf as {maxCallsPerMinute: number}).maxCallsPerMinute ?? limit })
          ),
        }),
      });

      await new Promise(() => {});
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
  });

// ── Scan Types ──
interface ScanFinding {
  severity: "critical" | "high" | "medium" | "low";
  ruleId: string;
  message: string;
  server?: string;
  tool?: string;
}

interface ToolScanResult {
  name: string;
  findings: ScanFinding[];
}

interface ServerScanResult {
  name: string;
  command: string;
  args: string[];
  findings: ScanFinding[];
  tools: ToolScanResult[];
  connected: boolean;
  connectionError?: string;
}

interface ScanReport {
  configPath: string;
  timestamp: string;
  serversScanned: number;
  toolsFound: number;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  exitCode: number;
  servers: ServerScanResult[];
  recommendations: string[];
}

// ── Scan constants ──
const SHELL_INJECTION_CHARS = /[;&|`$(){}<>\n\r]/;
const SUSPICIOUS_PATH_PATTERNS = [
  /\/tmp\//i,
  /\.\.[\/\\]/,
];
const PLAINTEXT_SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/^(ghp_|gho_|github_pat_)/, "GitHub token"],
  [/^(sk-[a-zA-Z0-9]{20,})/, "OpenAI key"],
  [/^(xoxb-|xoxp-|xoxa-)/, "Slack token"],
  [/^(AKIA[0-9A-Z]{16})/, "AWS access key"],
  [/^(eyJ[a-zA-Z0-9_-]{20,}\.)/, "JWT"],
  [/^[a-zA-Z0-9+/]{40,}={0,2}$/, "base64-encoded secret"],
];
const ENV_VAR_REFERENCE = /^\$\{[^}]+\}$/;
const SYSTEM_COMMANDS = new Set([
  "rm", "rmdir", "sudo", "su", "chmod", "chown", "chgrp",
  "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "rsync",
  "mv", "cp", "dd", "mkfs", "fdisk", "mount", "umount",
  "cat", "less", "more", "head", "tail", "grep", "awk", "sed",
  "ls", "find", "locate", "which", "whereis",
  "kill", "killall", "pkill", "shutdown", "reboot", "halt",
  "iptables", "firewall", "ufw",
  "base64", "xxd", "od",
  "python", "python3", "perl", "ruby", "php", "node", "bash", "sh", "zsh",
  "docker", "podman", "kubectl",
  "git", "svn", "hg",
  "tar", "zip", "unzip", "gzip", "gunzip",
  "env", "export", "set", "unset",
  "passwd", "useradd", "userdel", "usermod",
  "crontab", "at", "batch",
]);
const SUSPICIOUS_TOOL_NAME_PATTERNS = [
  { pattern: /^(file|fs)_?(system|manager|explorer|browser)/i, id: "name-mimics-filesystem" },
  { pattern: /^(system|os|kernel|admin|root|superuser)/i, id: "name-mimics-system" },
  { pattern: /^(network|net)_?(tool|util|manager)/i, id: "name-mimics-network" },
  { pattern: /^(exec|run|shell|terminal|cmd|command)/i, id: "name-mimics-executor" },
];

function scanServerConfig(
  name: string,
  srvConfig: { command?: string; args?: string[]; env?: Record<string, string> }
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const cmd = srvConfig.command ?? "";

  // Shell injection in command
  if (SHELL_INJECTION_CHARS.test(cmd)) {
    findings.push({
      severity: "critical",
      ruleId: "command-shell-injection",
      message: `Command contains shell metacharacters that may enable injection: "${cmd}"`,
      server: name,
    });
  }

  // Suspicious paths
  for (const pat of SUSPICIOUS_PATH_PATTERNS) {
    if (pat.test(cmd)) {
      findings.push({
        severity: "high",
        ruleId: "command-suspicious-path",
        message: `Command uses a suspicious path: "${cmd}"`,
        server: name,
      });
      break;
    }
  }

  // Shell injection in args
  for (const arg of srvConfig.args ?? []) {
    if (SHELL_INJECTION_CHARS.test(arg)) {
      findings.push({
        severity: "high",
        ruleId: "args-shell-injection",
        message: `Argument contains shell metacharacters: "${arg}"`,
        server: name,
      });
    }
  }

  // Env var checks
  for (const [key, val] of Object.entries(srvConfig.env ?? {})) {
    if (ENV_VAR_REFERENCE.test(val)) continue;

    let caught = false;
    for (const [pat, label] of PLAINTEXT_SECRET_PATTERNS) {
      if (pat.test(val)) {
        findings.push({
          severity: "critical",
          ruleId: "env-plaintext-secret",
          message: `Env var "${key}" contains what appears to be a plaintext ${label}. Use \${ENV_VAR} references instead.`,
          server: name,
        });
        caught = true;
        break;
      }
    }

    if (!caught && val.length > 20 && /^[a-zA-Z0-9_\-]{20,}$/.test(val)) {
      findings.push({
        severity: "medium",
        ruleId: "env-suspicious-value",
        message: `Env var "${key}" has a long opaque value that may be a hardcoded secret. Use \${ENV_VAR} references.`,
        server: name,
      });
    }

    if (val === "") {
      findings.push({
        severity: "low",
        ruleId: "env-empty-value",
        message: `Env var "${key}" is empty. This may cause unexpected behavior.`,
        server: name,
      });
    }
  }

  if (!cmd && !srvConfig.command) {
    findings.push({
      severity: "medium",
      ruleId: "command-missing",
      message: "Server has no command specified. It may be a remote-only config or misconfigured.",
      server: name,
    });
  }

  return findings;
}

function scanToolName(name: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const baseName = name.includes("__") ? name.split("__").pop()! : name;

  if (SYSTEM_COMMANDS.has(baseName.toLowerCase())) {
    findings.push({
      severity: "high",
      ruleId: "tool-name-squatting",
      message: `Tool name "${baseName}" mimics a system command. Could trick users into dangerous operations.`,
      tool: name,
    });
  }

  for (const { pattern, id } of SUSPICIOUS_TOOL_NAME_PATTERNS) {
    if (pattern.test(baseName)) {
      findings.push({
        severity: "medium",
        ruleId: id,
        message: `Tool name "${baseName}" suggests elevated system access.`,
        tool: name,
      });
    }
  }

  return findings;
}

program
  .command("scan")
  .description("Audit MCP server configurations for security issues (npm audit for MCP)")
  .argument("[config-path]", "Path to gateway config file")
  .option("-c, --config <path>", "Path to gateway config file")
  .option("--claude-desktop", "Auto-detect and scan Claude Desktop config")
  .option("--stdin", "Read config from stdin (for piping)")
  .option("--json", "Output machine-readable JSON report")
  .option("--fix", "Auto-generate a hardened config to stdout")
  .option("--connect", "Try to connect to running servers and list tools (slower)")
  .option("--timeout <ms>", "Connection timeout per server in ms", "10000")
  .action(async (configPathArg: string | undefined, opts: Record<string, string | boolean | undefined>) => {
    // ── Resolve config source ──
    let configRaw: string = "";
    let configSource: string = "";

    try {
      if (opts.stdin) {
        const chunks: Buffer[] = [];
        for await (const chunk of process.stdin) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        configRaw = Buffer.concat(chunks).toString("utf-8");
        configSource = "stdin";
      } else if (opts.claudeDesktop) {
        const claudePaths: string[] = [
          resolve(homedir(), ".config", "Claude", "claude_desktop_config.json"),
          resolve(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json"),
          resolve(homedir(), "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
        ];

        // WSL: check Windows paths
        const wslBase = "/mnt/c/Users";
        try {
          const users = readdirSync(wslBase);
          for (const user of users) {
            claudePaths.push(`${wslBase}/${user}/AppData/Roaming/Claude/claude_desktop_config.json`);
          }
        } catch { /* not WSL or no access */ }

        let found = false;
        for (const p of claudePaths) {
          if (existsSync(p)) {
            configRaw = await readFile(p, "utf-8");
            configSource = p;
            found = true;
            break;
          }
        }
        if (!found) {
          process.stderr.write("Error: Could not find Claude Desktop config.\nSearched:\n");
          for (const p of claudePaths) process.stderr.write(`  - ${p}\n`);
          process.exit(1);
        }
      } else {
        const cfgPath = (configPathArg ?? opts.config ?? "mcp-gateway.json") as string;
        configSource = resolve(cfgPath);
        configRaw = await readFile(configSource, "utf-8");
      }
    } catch (err) {
      process.stderr.write(`Error: Could not read config: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    }

    // ── Parse config ──
    let config: GatewayConfig;
    try {
      config = JSON.parse(configRaw);
    } catch {
      process.stderr.write(`Error: Invalid JSON in ${configSource}\n`);
      process.exit(1);
    }

    if (!config.servers || Object.keys(config.servers).length === 0) {
      process.stderr.write("Error: No servers defined in config\n");
      process.exit(1);
    }

    // ── Perform scan ──
    const serverResults: ServerScanResult[] = [];
    const recommendations: string[] = [];
    let toolsFound = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const [name, srvConfig] of Object.entries(config.servers)) {
      const serverFindings = scanServerConfig(name, srvConfig);
      const toolResults: ToolScanResult[] = [];
      let connected = false;
      let connectionError: string | undefined;

      // Try connecting to list tools
      if (opts.connect && srvConfig.command) {
        try {
          const timeout = parseInt((opts.timeout as string) ?? "10000", 10);
          const transport = new StdioClientTransport({
            command: srvConfig.command,
            args: srvConfig.args,
            env: srvConfig.env as Record<string, string> | undefined,
          });

          const client = new Client(
            { name: `mcp-gateway-scanner-${name}`, version: "0.1.0" },
            { capabilities: {} }
          );

          const connectPromise = client.connect(transport);
          const timeoutPromise = new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`Connection timed out after ${timeout}ms`)), timeout)
          );

          await Promise.race([connectPromise, timeoutPromise]);
          connected = true;

          try {
            const response = await client.listTools();
            toolsFound += response.tools.length;

            for (const tool of response.tools) {
              const toolFindings: ScanFinding[] = [];

              // Scan description for prompt injection
              const descFindings = scanToolDescription(tool.description ?? "");
              for (const f of descFindings) {
                toolFindings.push({
                  severity: f.severity,
                  ruleId: f.ruleId,
                  message: f.message,
                  server: name,
                  tool: tool.name,
                });
              }

              // Tool name squatting
              for (const f of scanToolName(tool.name)) {
                toolFindings.push({ ...f, server: name, tool: tool.name });
              }

              // Oversized description
              const desc = tool.description ?? "";
              if (desc.length > 5000) {
                toolFindings.push({
                  severity: "medium",
                  ruleId: "tool-description-oversized",
                  message: `Tool "${tool.name}" has an unusually large description (${desc.length} chars). Could hide prompt injection.`,
                  server: name,
                  tool: tool.name,
                });
              }

              // HTML comments in description
              if (/<!--/.test(desc)) {
                toolFindings.push({
                  severity: "high",
                  ruleId: "tool-description-hidden-html",
                  message: `Tool "${tool.name}" contains HTML comments that could hide malicious instructions.`,
                  server: name,
                  tool: tool.name,
                });
              }

              // Invisible unicode characters
              if (/[\u200b\u200c\u200d\ufeff\u00ad]/.test(desc)) {
                toolFindings.push({
                  severity: "high",
                  ruleId: "tool-description-invisible-chars",
                  message: `Tool "${tool.name}" contains invisible Unicode characters in its description.`,
                  server: name,
                  tool: tool.name,
                });
              }

              toolResults.push({ name: tool.name, findings: toolFindings });
            }
          } catch (err) {
            connectionError = `Connected but failed to list tools: ${err instanceof Error ? err.message : String(err)}`;
          }

          try { await client.close(); } catch { /* ignore */ }
        } catch (err) {
          connectionError = err instanceof Error ? err.message : String(err);
        }
      }

      // Count findings
      for (const f of serverFindings) {
        if (f.severity === "critical") criticalCount++;
        else if (f.severity === "high") highCount++;
        else if (f.severity === "medium") mediumCount++;
        else lowCount++;
      }
      for (const t of toolResults) {
        for (const f of t.findings) {
          if (f.severity === "critical") criticalCount++;
          else if (f.severity === "high") highCount++;
          else if (f.severity === "medium") mediumCount++;
          else lowCount++;
        }
      }

      serverResults.push({
        name,
        command: srvConfig.command ?? "(none)",
        args: srvConfig.args ?? [],
        findings: serverFindings,
        tools: toolResults,
        connected,
        connectionError,
      });
    }

    // ── Generate recommendations ──
    const totalIssues = criticalCount + highCount + mediumCount + lowCount;

    if (criticalCount > 0) {
      recommendations.push("CRITICAL: Address all critical findings immediately. These represent active security risks.");
    }
    if (serverResults.some(s => s.findings.some(f => f.ruleId === "env-plaintext-secret"))) {
      recommendations.push("Replace plaintext secrets with env var references (${VAR_NAME}).");
    }
    if (serverResults.some(s => s.findings.some(f => f.ruleId === "command-shell-injection"))) {
      recommendations.push("Fix shell injection vulnerabilities. Avoid shell metacharacters in commands/args.");
    }
    if (serverResults.some(s => s.tools.some(t => t.findings.some(f => f.ruleId === "tool-name-squatting")))) {
      recommendations.push("Review tools mimicking system commands. Verify their provenance and trustworthiness.");
    }
    if (serverResults.some(s => s.tools.some(t => t.findings.some(f => f.ruleId.startsWith("poison-"))))) {
      recommendations.push("Tool descriptions contain prompt injection patterns. Consider removing these servers.");
    }
    if (!config.policies?.security?.scanDescriptions) {
      recommendations.push("Enable security.scanDescriptions to catch prompt injection at runtime.");
    }
    if (!config.policies?.security?.blockOnCritical) {
      recommendations.push("Enable security.blockOnCritical to auto-block tools with critical findings.");
    }
    if (!config.audit?.enabled) {
      recommendations.push("Enable audit logging to maintain a record of all tool invocations.");
    }
    if (opts.connect && serverResults.some(s => !s.connected && s.connectionError)) {
      recommendations.push("Some servers could not be reached. Verify they are running and accessible.");
    }
    if (totalIssues === 0) {
      recommendations.push("No issues found. Your MCP configuration looks secure.");
    }

    // ── Build report ──
    const exitCode = criticalCount > 0 ? 2 : (highCount > 0 || mediumCount > 0) ? 1 : 0;
    const report: ScanReport = {
      configPath: configSource,
      timestamp: new Date().toISOString(),
      serversScanned: serverResults.length,
      toolsFound,
      totalIssues,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      exitCode,
      servers: serverResults,
      recommendations,
    };

    // ── --fix: generate hardened config ──
    if (opts.fix) {
      const hardened: GatewayConfig = JSON.parse(JSON.stringify(config));

      if (!hardened.policies) hardened.policies = {};
      if (!hardened.policies.security) {
        hardened.policies.security = {
          blockOnCritical: true,
          blockOnHigh: true,
          scanDescriptions: true,
          scanInputs: true,
          descriptorBaselinePath: "./.mcp-gateway-descriptors.json",
          descriptorChangeAction: "warn",
        };
      } else {
        hardened.policies.security.blockOnCritical = true;
        hardened.policies.security.blockOnHigh = true;
        hardened.policies.security.scanDescriptions = true;
        hardened.policies.security.scanInputs = true;
      }

      if (!hardened.audit) {
        hardened.audit = { enabled: true, logPath: "./mcp-audit.jsonl", includeArgs: true, includeResults: false };
      } else {
        hardened.audit.enabled = true;
      }

      if (!hardened.policies.rateLimit) {
        hardened.policies.rateLimit = { maxCallsPerMinute: 30, maxCallsPerHour: 500 };
      }

      // Sanitize env vars: replace likely secrets with placeholders
      for (const [, srv] of Object.entries(hardened.servers)) {
        if (srv.env) {
          for (const [key, val] of Object.entries(srv.env)) {
            if (!ENV_VAR_REFERENCE.test(val) && val.length > 8) {
              srv.env[key] = `\${${key}}`;
            }
          }
        }
      }

      const fixComment = [
        "// Hardened MCP Gateway Configuration",
        `// Generated by mcp-gateway scan --fix on ${new Date().toISOString()}`,
        "// Security scanning enabled, secrets replaced with env var references.",
        "",
      ].join("\n");

      process.stdout.write(fixComment + JSON.stringify(hardened, null, 2) + "\n");
      process.exit(exitCode);
    }

    // ── --json output ──
    if (opts.json) {
      process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      process.exit(report.exitCode);
    }

    // ── Human-readable output ──
    const sevIcon = (s: string) => {
      switch (s) {
        case "critical": return "🔴";
        case "high":     return "🟠";
        case "medium":   return "🟡";
        case "low":      return "🔵";
        default:         return "⚪";
      }
    };

    process.stdout.write("\n");
    process.stdout.write("  ┌─────────────────────────────────────────────┐\n");
    process.stdout.write("  │         MCP Gateway Security Scan            │\n");
    process.stdout.write("  └─────────────────────────────────────────────┘\n\n");

    process.stdout.write("  Summary\n");
    process.stdout.write("  ─────────────────────────────────────\n");
    process.stdout.write(`  Config:    ${configSource}\n`);
    process.stdout.write(`  Scanned:   ${report.serversScanned} server(s), ${report.toolsFound} tool(s)\n`);
    process.stdout.write(`  Issues:    ${report.totalIssues} total\n`);
    if (criticalCount > 0) process.stdout.write(`             ${sevIcon("critical")} ${criticalCount} critical\n`);
    if (highCount > 0) process.stdout.write(`             ${sevIcon("high")} ${highCount} high\n`);
    if (mediumCount > 0) process.stdout.write(`             ${sevIcon("medium")} ${mediumCount} medium\n`);
    if (lowCount > 0) process.stdout.write(`             ${sevIcon("low")} ${lowCount} low\n`);
    if (report.totalIssues === 0) process.stdout.write("             ✅ No issues found!\n");
    process.stdout.write("\n");

    for (const server of serverResults) {
      process.stdout.write(`  Server: ${server.name}\n`);
      process.stdout.write(`  Command: ${server.command} ${(server.args ?? []).join(" ")}\n`);

      if (opts.connect) {
        process.stdout.write(`  Status:  ${server.connected ? "✅ connected" : `❌ ${server.connectionError ?? "not connected"}`}\n`);
      }

      if (server.findings.length === 0 && server.tools.length === 0) {
        process.stdout.write("  ✅ No issues\n\n");
        continue;
      }

      for (const f of server.findings) {
        process.stdout.write(`  ${sevIcon(f.severity)} [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.message}\n`);
      }

      for (const tool of server.tools) {
        if (tool.findings.length > 0) {
          process.stdout.write(`  Tool: ${tool.name}\n`);
          for (const f of tool.findings) {
            process.stdout.write(`    ${sevIcon(f.severity)} [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.message}\n`);
          }
        } else if (opts.connect) {
          process.stdout.write(`  Tool: ${tool.name} ✅\n`);
        }
      }
      process.stdout.write("\n");
    }

    if (recommendations.length > 0) {
      process.stdout.write("  Recommendations\n");
      process.stdout.write("  ─────────────────────────────────────\n");
      for (let i = 0; i < recommendations.length; i++) {
        process.stdout.write(`  ${i + 1}. ${recommendations[i]}\n`);
      }
      process.stdout.write("\n");
    }

    if (exitCode === 0) {
      process.stdout.write("  ✅ All clear. No security issues found.\n\n");
    } else if (exitCode === 1) {
      process.stdout.write("  ⚠️  Warnings found. Review the issues above.\n\n");
    } else {
      process.stdout.write("  🚨 Critical issues found! Immediate action required.\n\n");
    }

    process.exit(exitCode);
  });

program.parse();
