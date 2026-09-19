/**
 * MCP-Sentinel: Risk Engine
 * Deterministic, explainable risk scoring (0–100).
 * Every risk update MUST have an explanation.
 */

import type {
  RiskAssessment,
  RiskFactors,
  RiskWeights,
  SecurityState,
  SentinelConfig,
  BehaviorDriftFinding,
} from "./types.js";

export class RiskEngine {
  private config: SentinelConfig;
  private riskHistory: Map<string, RiskAssessment[]> = new Map();

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  /**
   * Calculate risk score from evidence.
   * Returns a fully explainable RiskAssessment.
   */
  assess(entityId: string, evidence: RiskEvidence): RiskAssessment {
    const weights = this.config.risk.weights;
    const factors: RiskFactors = {
      integrity: 0,
      behavior: 0,
      runtime: 0,
      authorization: 0,
      sensitivity: 0,
      anomaly: 0,
    };
    const reasons: string[] = [];

    // ── Integrity Factor ──
    if (evidence.descriptorChanged) {
      factors.integrity = weights.integrity;
      reasons.push("Tool descriptor changed since baseline");
    }
    if (evidence.baselineMissing) {
      factors.integrity = Math.max(factors.integrity, weights.integrity * 0.3);
      reasons.push("No baseline exists for comparison");
    }

    // ── Behavior Factor ──
    if (evidence.driftFindings && evidence.driftFindings.length > 0) {
      let behaviorScore = 0;
      for (const finding of evidence.driftFindings) {
        behaviorScore += finding.riskContribution;
        if (finding.type !== "BEHAVIOR_DRIFT") {
          reasons.push(finding.message);
        }
      }
      factors.behavior = Math.min(behaviorScore, weights.behavior);
    }

    // ── Runtime Factor ──
    if (evidence.runtimeViolations && evidence.runtimeViolations.length > 0) {
      let runtimeScore = 0;
      for (const violation of evidence.runtimeViolations) {
        runtimeScore += violation.severity === "critical" ? 10 : violation.severity === "high" ? 7 : 4;
        reasons.push(`Runtime: ${violation.message}`);
      }
      factors.runtime = Math.min(runtimeScore, weights.runtime);
    }

    // ── Authorization Factor ──
    if (evidence.unauthorizedAccess) {
      factors.authorization = weights.authorization;
      reasons.push("Unauthorized access attempt detected");
    }
    if (evidence.capabilityMismatch) {
      factors.authorization = Math.max(factors.authorization, weights.authorization * 0.8);
      reasons.push("Observed capability exceeds authorized capability");
    }
    if (evidence.missingAuth) {
      factors.authorization = Math.max(factors.authorization, weights.authorization * 0.5);
      reasons.push("Missing or invalid authentication");
    }

    // ── Sensitivity Factor ──
    if (evidence.sensitiveDataAccess) {
      factors.sensitivity = weights.sensitivity;
      reasons.push("Tool accessed sensitive data");
    }
    if (evidence.sensitiveFileAccess) {
      factors.sensitivity = Math.max(factors.sensitivity, weights.sensitivity * 0.8);
      reasons.push("Tool accessed a sensitive file");
    }

    // ── Anomaly Factor ──
    if (evidence.frequencyAnomaly) {
      factors.anomaly = weights.anomaly * 0.5;
      reasons.push("Unusual call frequency detected");
    }
    if (evidence.previousIncidents && evidence.previousIncidents > 0) {
      factors.anomaly = Math.max(factors.anomaly, weights.anomaly * Math.min(evidence.previousIncidents * 0.3, 1));
      reasons.push(`${evidence.previousIncidents} previous incident(s) recorded`);
    }
    if (evidence.outputAnomaly) {
      factors.anomaly = Math.max(factors.anomaly, weights.anomaly * 0.6);
      reasons.push("Suspicious output patterns detected");
    }

    // ── Calculate total (bounded 0–100) ──
    const rawScore = Object.values(factors).reduce((sum, v) => sum + v, 0);
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));

    // Get previous assessment
    const history = this.riskHistory.get(entityId) ?? [];
    const previous = history.length > 0 ? history[history.length - 1] : null;
    const previousScore = previous?.score ?? 0;

    const assessment: RiskAssessment = {
      score,
      previousScore,
      delta: score - previousScore,
      state: this.scoreToState(score),
      reasons: reasons.length > 0 ? reasons : ["No risk indicators detected"],
      factors,
      timestamp: new Date().toISOString(),
      toolId: evidence.toolId,
      serverId: evidence.serverId,
    };

    // Store in history
    history.push(assessment);
    if (history.length > 100) history.shift();
    this.riskHistory.set(entityId, history);

    return assessment;
  }

  /**
   * Get aggregate risk for a server based on all its tools.
   */
  aggregateServerRisk(toolAssessments: RiskAssessment[]): number {
    if (toolAssessments.length === 0) return 0;
    // Use the maximum tool risk score as the server risk
    return Math.max(...toolAssessments.map(a => a.score));
  }

  /**
   * Map a risk score to a security state using configured thresholds.
   */
  scoreToState(score: number): SecurityState {
    const t = this.config.risk.thresholds;
    if (score >= t.quarantine) return "QUARANTINE";
    if (score >= t.approval) return "HUMAN_APPROVAL";
    if (score >= t.restrict) return "RESTRICT";
    if (score >= t.monitor) return "MONITOR";
    return "NORMAL";
  }

  /**
   * Get risk history for an entity.
   */
  getHistory(entityId: string, limit = 50): RiskAssessment[] {
    const history = this.riskHistory.get(entityId) ?? [];
    return history.slice(-limit);
  }

  /**
   * Get the latest risk assessment for an entity.
   */
  getLatest(entityId: string): RiskAssessment | undefined {
    const history = this.riskHistory.get(entityId);
    return history && history.length > 0 ? history[history.length - 1] : undefined;
  }

  /**
   * Create a risk timeline for the dashboard.
   */
  getTimeline(limit = 200): Array<{ timestamp: string; entityId: string; score: number; state: SecurityState }> {
    const timeline: Array<{ timestamp: string; entityId: string; score: number; state: SecurityState }> = [];
    for (const [entityId, history] of this.riskHistory) {
      for (const a of history) {
        timeline.push({ timestamp: a.timestamp, entityId, score: a.score, state: a.state });
      }
    }
    return timeline
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
      .slice(-limit);
  }
}

/**
 * Evidence input to the risk engine.
 * All fields are optional — only provide what's observed.
 */
export interface RiskEvidence {
  toolId?: string;
  serverId?: string;

  // Integrity
  descriptorChanged?: boolean;
  baselineMissing?: boolean;

  // Behavior
  driftFindings?: BehaviorDriftFinding[];

  // Runtime
  runtimeViolations?: Array<{
    severity: "low" | "medium" | "high" | "critical";
    message: string;
  }>;

  // Authorization
  unauthorizedAccess?: boolean;
  capabilityMismatch?: boolean;
  missingAuth?: boolean;

  // Sensitivity
  sensitiveDataAccess?: boolean;
  sensitiveFileAccess?: boolean;

  // Anomaly
  frequencyAnomaly?: boolean;
  previousIncidents?: number;
  outputAnomaly?: boolean;
}
