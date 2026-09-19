/**
 * MCP-Sentinel: Security State Machine
 * NORMAL → MONITOR → RESTRICT → HUMAN_APPROVAL → QUARANTINE
 * Implements hysteresis/cooldown to prevent rapid oscillation.
 */

import type { SecurityState, SentinelConfig } from "./types.js";

export interface StateTransition {
  from: SecurityState;
  to: SecurityState;
  reason: string;
  riskScore: number;
  timestamp: string;
}

interface StateEntry {
  state: SecurityState;
  enteredAt: number;
  riskScore: number;
  consecutiveCount: number;
}

const STATE_ORDER: SecurityState[] = ["NORMAL", "MONITOR", "RESTRICT", "HUMAN_APPROVAL", "QUARANTINE"];

export class SecurityStateMachine {
  private config: SentinelConfig;
  private states: Map<string, StateEntry> = new Map();
  private transitions: StateTransition[] = [];

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  /**
   * Evaluate risk score and determine if a state transition is needed.
   * Implements hysteresis to prevent oscillation.
   */
  evaluate(entityId: string, riskScore: number): {
    currentState: SecurityState;
    newState: SecurityState;
    transition: StateTransition | null;
  } {
    const targetState = this.scoreToState(riskScore);
    const current = this.states.get(entityId);

    if (!current) {
      // First evaluation — set initial state
      this.states.set(entityId, {
        state: targetState,
        enteredAt: Date.now(),
        riskScore,
        consecutiveCount: 1,
      });
      const transition: StateTransition = {
        from: "NORMAL",
        to: targetState,
        reason: `Initial state set based on risk score ${riskScore}`,
        riskScore,
        timestamp: new Date().toISOString(),
      };
      if (targetState !== "NORMAL") {
        this.transitions.push(transition);
        return { currentState: targetState, newState: targetState, transition };
      }
      return { currentState: targetState, newState: targetState, transition: null };
    }

    const currentState = current.state;
    current.riskScore = riskScore;

    // Same state — no transition
    if (currentState === targetState) {
      current.consecutiveCount++;
      return { currentState, newState: currentState, transition: null };
    }

    const isEscalation = STATE_ORDER.indexOf(targetState) > STATE_ORDER.indexOf(currentState);
    const now = Date.now();
    const timeInState = now - current.enteredAt;
    const { margin, cooldownMs } = this.config.risk.hysteresis;

    if (isEscalation) {
      // Escalation — apply immediately (security takes priority)
      const transition = this.doTransition(entityId, currentState, targetState, riskScore,
        `Risk escalated from ${currentState} to ${targetState} (score: ${riskScore})`);
      return { currentState, newState: targetState, transition };
    } else {
      // De-escalation — apply hysteresis
      // Must: 1) be below threshold by margin, 2) have been in current state for cooldown period
      const thresholdForCurrent = this.getThresholdForState(currentState);
      const belowByMargin = riskScore <= (thresholdForCurrent - margin);
      const cooldownSatisfied = timeInState >= cooldownMs;

      if (belowByMargin && cooldownSatisfied) {
        const transition = this.doTransition(entityId, currentState, targetState, riskScore,
          `Risk de-escalated from ${currentState} to ${targetState} (score: ${riskScore}, cooldown satisfied)`);
        return { currentState, newState: targetState, transition };
      }

      // De-escalation conditions not met
      return { currentState, newState: currentState, transition: null };
    }
  }

  /**
   * Force a state transition (for quarantine/recovery).
   */
  forceTransition(entityId: string, newState: SecurityState, reason: string, riskScore: number): StateTransition {
    const current = this.states.get(entityId);
    const fromState = current?.state ?? "NORMAL";
    return this.doTransition(entityId, fromState, newState, riskScore, reason);
  }

  getState(entityId: string): SecurityState {
    return this.states.get(entityId)?.state ?? "NORMAL";
  }

  getTransitions(limit = 50): StateTransition[] {
    return this.transitions.slice(-limit);
  }

  /** Clears all tracked states and transition history. */
  reset(): void {
    this.states.clear();
    this.transitions = [];
  }

  private doTransition(
    entityId: string,
    from: SecurityState,
    to: SecurityState,
    riskScore: number,
    reason: string,
  ): StateTransition {
    this.states.set(entityId, {
      state: to,
      enteredAt: Date.now(),
      riskScore,
      consecutiveCount: 1,
    });

    const transition: StateTransition = {
      from,
      to,
      reason,
      riskScore,
      timestamp: new Date().toISOString(),
    };
    this.transitions.push(transition);
    if (this.transitions.length > 1000) {
      this.transitions = this.transitions.slice(-1000);
    }
    return transition;
  }

  private scoreToState(score: number): SecurityState {
    const t = this.config.risk.thresholds;
    if (score >= t.quarantine) return "QUARANTINE";
    if (score >= t.approval) return "HUMAN_APPROVAL";
    if (score >= t.restrict) return "RESTRICT";
    if (score >= t.monitor) return "MONITOR";
    return "NORMAL";
  }

  private getThresholdForState(state: SecurityState): number {
    const t = this.config.risk.thresholds;
    switch (state) {
      case "QUARANTINE": return t.quarantine;
      case "HUMAN_APPROVAL": return t.approval;
      case "RESTRICT": return t.restrict;
      case "MONITOR": return t.monitor;
      default: return 0;
    }
  }
}
