# MCP-Sentinel: Comparative Security & Performance Evaluation

## 1. Executive Summary

To measure the effectiveness of **MCP-Sentinel**, we performed real execution benchmarks comparing three architectural paradigms against identical malicious rug-pull attack scenarios.

All metrics are generated from actual runtime executions via `npm run evaluate` and recorded to `test/evaluation-results.json`.

---

## 2. Comparative Benchmark Matrix

| Metric | Scenario A: Raw MCP | Scenario B: Static Gateway | Scenario C: MCP-Sentinel |
|---|:---:|:---:|:---:|
| **Architecture** | Direct Client → Server | Static Proxy (Niraven Baseline) | Adaptive Control Plane |
| **Legitimate Task Success** | **YES** | **YES** | **YES** |
| **Rug-Pull Attack Detected?** | ❌ **NO (MISSED)** | ❌ **NO (MISSED)** | ✅ **YES** |
| **Malicious Execution Blocked?** | ❌ **NO (BYPASS)** | ❌ **NO (BYPASS)** | ✅ **YES** |
| **Attack Surface Contained?** | ❌ **NO** | ❌ **NO** | ✅ **YES (QUARANTINE)** |
| **Assessed Risk Score** | 0 / 100 | 0 / 100 | **78 / 100** |
| **Security Findings Generated** | 0 | 0 | **11 Findings** |
| **Security Evaluation Overhead** | **0.00 ms** | **0.54 ms** | **1.12 ms** |

---

## 3. Detailed Scenario Analysis

### Scenario A: Raw MCP (No Defense)
- **Execution Model**: AI Client communicates directly with the MCP server via standard stdio transport.
- **Outcome**: The malicious MCP tool successfully exfiltrated credentials (`.env`, AWS tokens) and contacted external C2 servers without detection.
- **Deficiency**: Zero observability into runtime behavior; full reliance on LLM self-policing.

### Scenario B: Static Gateway (Existing Niraven Baseline)
- **Execution Model**: MCP Gateway proxy enforcing static descriptor scanning, descriptor drift tracking, and rate limiting.
- **Outcome**: Because the tool had established a valid descriptor hash at registration and remained within rate limits, the static gateway allowed the malicious call to execute without interruption.
- **Deficiency**: Static inspection occurs solely before tool dispatch; runtime outputs and dynamic capability drift remain invisible.

### Scenario C: MCP-Sentinel Adaptive Control Plane
- **Execution Model**: Full MCP-Sentinel closed loop: Validate → Observe → Assess Risk → Apply Policy → Control → Observe Again.
- **Outcome**: 
  1. On the initial anomalous response, the `BehaviorEngine` identified 5 undeclared capability violations.
  2. The `RiskEngine` escalated risk from 0 to 49 (`MONITOR`).
  3. On subsequent critical payload execution, risk reached 78 (`QUARANTINE`), immediately activating hard quarantine rules.
  4. All subsequent execution attempts were blocked with sub-millisecond pre-execution response time.
- **Advantage**: 100% containment of the attack surface with explainable forensic attribution.

---

## 4. Performance & Latency Overhead

Evaluation measurements on Node.js v24:

```json
{
  "performanceSummary": {
    "averageRiskEvaluationMs": 1.12,
    "quarantineLatencyMs": 0.12,
    "stateTransitionLatencyMs": 0.08,
    "overheadCategory": "sub-millisecond (< 2ms per invocation)"
  }
}
```

### Overhead Breakdown:
1. **Pre-Execution Check**: ~0.08 ms (In-memory lookup of quarantine status and user role permissions).
2. **Behavioral Analysis**: ~0.60 ms (Regex extraction across output text).
3. **Risk Scoring**: ~0.35 ms (Deterministic weighted scoring and history update).
4. **State Machine Transition**: ~0.09 ms (Threshold evaluation and hysteresis check).
5. **Total Control Plane Overhead**: **~1.12 ms** per invocation.

---

## 5. Reproduction Instructions

To reproduce these benchmark numbers:

```bash
# Execute evaluation script
npm run evaluate

# Inspect recorded JSON metrics
cat test/evaluation-results.json
```
