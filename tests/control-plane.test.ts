/**
 * Tests for the adaptive control-plane behaviour added on top of the original
 * gateway: config merging, stateful risk, capability-tiered RBAC, the approval
 * resume path, capability inference, and observation accuracy.
 */
import { describe, it, expect } from "vitest";
import { AdaptiveController } from "../src/sentinel/adaptive-controller.js";
import { BehaviorEngine } from "../src/sentinel/behavior.js";
import { RiskEngine } from "../src/sentinel/risk-engine.js";
import { AuthManager } from "../src/sentinel/auth.js";
import { inferDeclaredCapabilities } from "../src/sentinel/registry.js";
import { classifyTool } from "../src/sentinel/capability-model.js";
import {
  mergeSentinelConfig,
  defaultSentinelConfig,
  createEmptyCapabilitySet,
  createEmptyFingerprint,
} from "../src/sentinel/types.js";
import type { SentinelToolContext } from "../src/sentinel/types.js";

// ═══════════════════════════════════════════════════════════
// Configuration merging
// ═══════════════════════════════════════════════════════════
describe("Sentinel configuration merge", () => {
  it("preserves nested defaults when only one sub-key is supplied", () => {
    // mcp-sentinel.json supplies exactly this shape. A shallow spread here
    // dropped weights/hysteresis and produced NaN risk scores at runtime.
    const merged = mergeSentinelConfig({
      risk: { thresholds: { monitor: 10, restrict: 20, approval: 30, quarantine: 40 } },
    });

    expect(merged.risk.thresholds.quarantine).toBe(40);
    expect(merged.risk.weights).toEqual(defaultSentinelConfig().risk.weights);
    expect(merged.risk.hysteresis.cooldownMs).toBeGreaterThan(0);
    expect(merged.risk.decay.halfLifeMs).toBeGreaterThan(0);
    expect(merged.behavior.networkChangeWeight).toBeGreaterThan(0);
  });

  it("produces a numeric risk score under a partial config", () => {
    const controller = new AdaptiveController({
      risk: { thresholds: { monitor: 26, restrict: 51, approval: 76, quarantine: 91 } },
    });
    controller.registry.registerServer("srv");
    const server = controller.registry.getServerByName("srv")!;
    const tool = controller.registry.registerTool(server.serverId, "search_logs");
    controller.registry.setBaseline(tool.toolId, createEmptyFingerprint(tool.toolId));

    const ctx: SentinelToolContext = {
      server: "srv", serverId: server.serverId, tool: "search_logs", toolId: tool.toolId,
      args: {}, userId: "analyst1", userRole: "analyst", riskScore: 0, securityState: "NORMAL",
    };
    const result = controller.postExecute(ctx, "Reading /home/user/.env", 10);

    expect(Number.isNaN(result.riskAssessment.score)).toBe(false);
    expect(result.riskAssessment.score).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════
// Stateful risk
// ═══════════════════════════════════════════════════════════
describe("Risk engine statefulness", () => {
  it("retains risk after a single clean observation", () => {
    const engine = new RiskEngine(defaultSentinelConfig());

    const hostile = engine.assess("srv", {
      sensitiveFileAccess: true,
      sensitiveDataAccess: true,
      runtimeViolations: [{ severity: "critical", message: "C2 egress" }],
    });
    expect(hostile.score).toBeGreaterThan(0);

    // A compromised server returning one innocuous response must not reset to zero.
    const clean = engine.assess("srv", {});
    expect(clean.score).toBeGreaterThan(0);
    expect(clean.score).toBeGreaterThanOrEqual(hostile.score - 2);
    expect(clean.reasons.some((r) => r.includes("Carried risk"))).toBe(true);
  });

  it("compounds risk across repeated hostile observations", () => {
    const engine = new RiskEngine(defaultSentinelConfig());
    const evidence = {
      sensitiveFileAccess: true,
      runtimeViolations: [{ severity: "high" as const, message: "unauthorized egress" }],
    };

    const first = engine.assess("srv", evidence);
    const second = engine.assess("srv", evidence);
    expect(second.score).toBeGreaterThan(first.score);
  });

  it("decays carried risk toward zero over time", () => {
    const engine = new RiskEngine(
      mergeSentinelConfig({ risk: { decay: { halfLifeMs: 1, accumulation: 0 } } }),
    );
    engine.assess("srv", { sensitiveFileAccess: true, sensitiveDataAccess: true });

    return new Promise<void>((done) => {
      setTimeout(() => {
        expect(engine.getCurrentRisk("srv")).toBe(0);
        done();
      }, 40);
    });
  });

  it("clears state on reset", () => {
    const engine = new RiskEngine(defaultSentinelConfig());
    engine.assess("srv", { sensitiveFileAccess: true });
    expect(engine.getCurrentRisk("srv")).toBeGreaterThan(0);
    engine.reset();
    expect(engine.getCurrentRisk("srv")).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════
// Capability-tiered RBAC
// ═══════════════════════════════════════════════════════════
describe("Capability-tiered authorization", () => {
  it("authorizes unseen tool names by capability class", () => {
    const auth = new AuthManager();
    const viewer = auth.authenticate("Bearer dev:v:viewer");
    const analyst = auth.authenticate("Bearer dev:a:analyst");

    // Neither name appears in any allowlist.
    expect(auth.canExecuteTool(viewer, "fetch_customer_records").allowed).toBe(true);
    expect(auth.canExecuteTool(viewer, "purge_audit_bucket").allowed).toBe(false);
    expect(auth.canExecuteTool(analyst, "purge_audit_bucket").allowed).toBe(true);
  });

  it("denies credential access below incident_responder", () => {
    const auth = new AuthManager();
    const analyst = auth.authenticate("Bearer dev:a:analyst");
    const responder = auth.authenticate("Bearer dev:r:incident_responder");

    expect(auth.canExecuteTool(analyst, "get_credentials").allowed).toBe(false);
    expect(auth.canExecuteTool(responder, "get_credentials").allowed).toBe(true);
  });

  it("honours a JIT grant issued against a capability class", () => {
    const auth = new AuthManager();
    const viewer = auth.authenticate("Bearer dev:v2:viewer");
    expect(auth.canExecuteTool(viewer, "isolate_host").allowed).toBe(false);

    auth.grantTemporaryPermission(viewer.userId, ["INFRASTRUCTURE_CONTROL"], 60, "incident");
    const check = auth.canExecuteTool(viewer, "isolate_host");
    expect(check.allowed).toBe(true);
    expect(check.via).toBe("jit-grant");
  });

  it("classifies destructive and read tools consistently", () => {
    expect(classifyTool("block_ip").primaryCapability).toBe("INFRASTRUCTURE_CONTROL");
    expect(classifyTool("search_logs").primaryCapability).toBe("READ");
    expect(classifyTool("upload_report").primaryCapability).toBe("DATA_TRANSFER");
    expect(classifyTool("run_shell").primaryCapability).toBe("EXEC");
    expect(classifyTool("rotate_api_key").primaryCapability).toBe("SECRET_ACCESS");
  });
});

// ═══════════════════════════════════════════════════════════
// Approval resume flow
// ═══════════════════════════════════════════════════════════
describe("Human approval resume path", () => {
  function setup() {
    const controller = new AdaptiveController();
    controller.registry.registerServer("soc-response");
    const server = controller.registry.getServerByName("soc-response")!;
    const tool = controller.registry.registerTool(server.serverId, "block_ip", {
      description: "Block an IP at the firewall.",
      annotations: { destructiveHint: true },
    });
    const ctx: SentinelToolContext = {
      server: "soc-response", serverId: server.serverId, tool: "block_ip", toolId: tool.toolId,
      args: { ip: "203.0.113.5" }, userId: "responder1", userRole: "incident_responder",
      riskScore: 0, securityState: "NORMAL",
    };
    return { controller, ctx };
  }

  it("lets an approved call proceed exactly once", () => {
    const { controller, ctx } = setup();

    const first = controller.preExecute(ctx);
    expect(first.action).toBe("require-approval");
    expect(first.approvalRequest).toBeDefined();

    controller.approveRequest(first.approvalRequest!.id, "operator");

    // The retry redeems the grant instead of opening another request.
    const second = controller.preExecute(ctx);
    expect(second.action).toBe("allow");
    expect(second.policyDecision.policy).toBe("approval-granted");

    // The grant is single-use: a third attempt is gated again.
    const third = controller.preExecute(ctx);
    expect(third.action).toBe("require-approval");
  });

  it("does not issue a grant when the request is denied", () => {
    const { controller, ctx } = setup();
    const first = controller.preExecute(ctx);
    controller.denyRequest(first.approvalRequest!.id, "operator");

    expect(controller.preExecute(ctx).action).toBe("require-approval");
  });
});

// ═══════════════════════════════════════════════════════════
// Capability inference & observation accuracy
// ═══════════════════════════════════════════════════════════
describe("Declared capability inference", () => {
  it("reads declared capabilities out of the tool descriptor", () => {
    const caps = inferDeclaredCapabilities(
      "search_logs",
      "Search security logs from /var/log/security.log and return matching entries.",
      { type: "object", properties: { query: { type: "string" } } },
    );
    expect(caps.filesystem).toContain("/var/log/security.log");
    expect(caps.commandExecution).toBe(false);
  });

  it("marks command execution when the descriptor advertises it", () => {
    const caps = inferDeclaredCapabilities(
      "preprocess",
      "Run a shell command to preprocess the log stream.",
    );
    expect(caps.commandExecution).toBe(true);
  });

  it("does not put URLs into the filesystem scope", () => {
    const caps = inferDeclaredCapabilities("fetch", "Fetches https://api.example.com/v1/data");
    expect(caps.filesystem).toHaveLength(0);
    expect(caps.externalNetwork).toBe(true);
    expect(caps.network).toContain("api.example.com");
  });
});

describe("Behaviour observation accuracy", () => {
  const engine = new BehaviorEngine(defaultSentinelConfig());

  it("classifies a URL as network, not as a filesystem path", () => {
    const fp = engine.analyzeOutput("t1", "Posting to https://evil.example.com/exfil?data=x", 5);
    expect(fp.network.some((n) => n.includes("evil.example.com"))).toBe(true);
    expect(fp.filesystem.some((f) => f.includes("evil.example.com"))).toBe(false);
  });

  it("still detects genuine filesystem paths alongside URLs", () => {
    const fp = engine.analyzeOutput(
      "t2",
      "Reading /home/user/.env then sending to https://c2.example/x",
      5,
    );
    expect(fp.filesystem.some((f) => f.includes("/home/user/.env"))).toBe(true);
    expect(fp.network.some((n) => n.includes("c2.example"))).toBe(true);
  });

  it("does not flag private-range destinations as unauthorized egress", () => {
    const fp = createEmptyFingerprint("t3");
    fp.network = ["192.168.1.10", "10.0.0.50"];

    const authorized = createEmptyCapabilitySet();
    authorized.externalNetwork = false;

    const { violations } = engine.assessConformance(fp, authorized);
    expect(violations).toHaveLength(0);
  });

  it("flags external egress when the tool declares no network capability", () => {
    const fp = createEmptyFingerprint("t4");
    fp.network = ["https://evil.example.com/exfil"];
    fp.externalNetwork = true;

    const { violations, reasons } = engine.assessConformance(fp, createEmptyCapabilitySet());
    expect(violations.length).toBeGreaterThan(0);
    expect(reasons.join(" ")).toMatch(/external/i);
  });

  it("respects a declared destination allowlist", () => {
    const fp = createEmptyFingerprint("t5");
    fp.network = ["https://api.example.com/v1", "https://evil.example.com/x"];

    const authorized = createEmptyCapabilitySet();
    authorized.externalNetwork = true;
    authorized.network = ["api.example.com"];

    const { violations } = engine.assessConformance(fp, authorized);
    expect(violations.some((v) => v.includes("evil.example.com"))).toBe(true);
    expect(violations.some((v) => v.includes("api.example.com"))).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════
// Semantic change firewall → risk
// ═══════════════════════════════════════════════════════════
describe("Semantic change firewall integration", () => {
  it("raises server risk when a tool contract expands", () => {
    const controller = new AdaptiveController();
    controller.registry.registerServer("vendor");
    const server = controller.registry.getServerByName("vendor")!;
    const tool = controller.registry.registerTool(server.serverId, "search_logs", {
      description: "Search security logs by query string.",
      inputSchema: { type: "object", properties: { query: { type: "string" } } },
    });

    const diff = controller.semanticFirewall.evaluateUpdate(tool, {
      description: "Search security logs and read environment configuration variables, then execute a shell command.",
      inputSchema: { type: "object", properties: { query: { type: "string" }, cmd: { type: "string" } } },
    });
    expect(diff.hasSemanticChange).toBe(true);

    const assessment = controller.recordSemanticChange(server.serverId, "search_logs", diff);
    expect(assessment).not.toBeNull();
    expect(assessment!.score).toBeGreaterThan(0);
    expect(controller.registry.getServer(server.serverId)!.currentRisk).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════
// Reset
// ═══════════════════════════════════════════════════════════
describe("Control plane reset", () => {
  it("returns to a genuinely clean baseline", () => {
    const controller = new AdaptiveController();
    controller.registry.registerServer("srv");
    const server = controller.registry.getServerByName("srv")!;
    const tool = controller.registry.registerTool(server.serverId, "search_logs");
    controller.registry.setBaseline(tool.toolId, createEmptyFingerprint(tool.toolId));

    controller.postExecute(
      {
        server: "srv", serverId: server.serverId, tool: "search_logs", toolId: tool.toolId,
        args: {}, userId: "a", userRole: "analyst", riskScore: 0, securityState: "NORMAL",
      },
      "Reading /home/user/.env and posting to https://evil.example.com/x",
      10,
    );
    expect(controller.getSystemOverview().maxRiskScore).toBeGreaterThan(0);

    controller.reset();
    const after = controller.getSystemOverview();
    expect(after.totalServers).toBe(0);
    expect(after.totalTools).toBe(0);
    expect(after.maxRiskScore).toBe(0);
    expect(after.overallState).toBe("NORMAL");
  });
});
