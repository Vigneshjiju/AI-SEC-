# MCP-Sentinel: Architectural Specification

## 1. System Overview

**MCP-Sentinel** is an adaptive security control plane for the Model Context Protocol (MCP). It operates as an intelligent proxy between AI Agents / MCP Clients and backend MCP servers.

Unlike traditional static proxies that only inspect descriptors or enforce fixed rate limits, MCP-Sentinel continuously observes tool behavior across execution lifecycles, compares observed execution against cryptographic baselines, dynamically scores risk, and adapts enforcement policies in real time.

```
                    ┌─────────────────────────┐
                    │  AI Agent / MCP Client  │
                    └────────────┬────────────┘
                                 │ JSON-RPC (MCP)
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         MCP-SENTINEL GATEWAY                           │
│                                                                        │
│   1. AUTH & IDENTITY       2. HARD SECURITY RULES                      │
│      Keycloak/Dev RBAC        Quarantine & Schema Validation           │
│              │                               │                         │
│              ▼                               ▼                         │
│   3. STATE EVALUATION      4. ADAPTIVE POLICY ENGINE                   │
│      Normal/Monitor/          Allow, Restrict, Human-Approval,         │
│      Restrict/Approval/Quar   Quarantine Enforcement                   │
│              │                               │                         │
│              ▼                               ▼                         │
│   5. UPSTREAM EXECUTION    6. BEHAVIORAL DRIFT ANALYSIS                │
│      Call MCP Server          Declared vs Authorized vs Observed       │
│              │                               │                         │
│              ▼                               ▼                         │
│   7. RISK ENGINE           8. STATE TRANSITION & TELEMETRY             │
│      Weighted 0-100 Score     Pub/Sub Event Bus & Audit Logging        │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │ Upstream Stdio / SSE
                                 ▼
                    ┌─────────────────────────┐
                    │       MCP Servers       │
                    │  SOC Tools / Marketplace│
                    └─────────────────────────┘
```

---

## 2. The Core Security Feedback Loop

MCP-Sentinel enforces the closed-loop cycle:

$$\text{Validate} \longrightarrow \text{Observe} \longrightarrow \text{Assess Risk} \longrightarrow \text{Apply Policy} \longrightarrow \text{Control} \longrightarrow \text{Observe Again} \circlearrowleft$$

1. **Validate**: Check caller identity, tool registration, and hard security rules (e.g. is the server quarantined? Does the user role permit this action?).
2. **Observe**: Capture tool execution response, output patterns, referenced file paths, network destinations, and execution duration.
3. **Assess Risk**: Feed observed findings into the weighted deterministic risk engine. Compute updated risk score (0–100) and identify contributing factors.
4. **Apply Policy**: Feed the updated risk score and context into the adaptive state machine. Transition state if thresholds are met.
5. **Control**: Enforce the security state on subsequent interactions (e.g., permit, require human approval, restrict destructive tools, or terminate all access via quarantine).
6. **Observe Again**: Continuous monitoring of all subsequent calls.

---

## 3. The Capability Model: Declared vs. Authorized vs. Observed

The core research paradigm of MCP-Sentinel addresses the divergence between what a tool says it does and what it actually does.

| Capability Layer | Definition | Storage Location |
|---|---|---|
| **Declared Capability** | What the tool author claims the tool accesses in its documentation or schema. | `ToolRegistration.declaredCapabilities` |
| **Authorized Capability** | What enterprise security policies permit this tool to access in production. | `ToolRegistration.authorizedCapabilities` |
| **Observed Capability** | What runtime observation discovers the tool accessing during actual execution. | `BehaviorFingerprint` (Current) |

### Detection Matrix:
- If $\text{Observed} \subseteq \text{Declared}$: **Conformant** (Risk Delta = 0).
- If $\text{Observed} \not\subseteq \text{Declared}$: **Behavioral Drift Detected** ($\Delta \text{Risk} > 0$).
- If $\text{Observed} \not\subseteq \text{Authorized}$: **Policy Violation / Hard Block Triggered**.

---

## 4. Subsystem Breakdown

### 4.1. Adaptive Controller (`src/sentinel/adaptive-controller.ts`)
The central orchestrator connecting all Sentinel modules. It handles:
- `preExecute(ctx)`: Invoked before tool dispatch. Checks server quarantine, verifies user permissions via `AuthManager`, evaluates state policies via `PolicyEngine`, and intercepts sensitive actions for human approval.
- `postExecute(ctx, output, duration)`: Invoked immediately following tool execution. Extracts output text, generates an observed `BehaviorFingerprint`, runs `compareFingerprint`, calculates risk via `RiskEngine`, evaluates state transitions via `SecurityStateMachine`, and triggers auto-quarantine if risk exceeds threshold.

### 4.2. Behavior Fingerprint Engine (`src/sentinel/behavior.ts`)
Inspects tool outputs and execution telemetry using structured regular expression extractors and pattern matching:
- **Filesystem Access**: Unix/Windows paths, `/etc/shadow`, `.env`, `.ssh/id_rsa`, `.aws/credentials`.
- **Network Exfiltration**: External HTTP/HTTPS URLs, IP addresses, WebSocket destinations.
- **Process Spawning**: `exec()`, `child_process`, `subprocess.Popen`, shell commands (`curl`, `sh`, `bash`).
- **Environment Access**: `process.env`, `os.environ`, API key patterns.
- Generates structured `BehaviorDriftFinding[]` with severity ratings (`critical`, `high`, `medium`, `low`).

### 4.3. Deterministic Risk Engine (`src/sentinel/risk-engine.ts`)
Computes an explainable score between 0 and 100:

$$\text{Risk} = \min\left(100, \sum_{i \in \text{factors}} \text{Weight}_i \times \text{ObservedSeverity}_i\right)$$

- **Configurable Weights**:
  - `behavior`: 30%
  - `runtime`: 20%
  - `integrity`: 15%
  - `authorization`: 15%
  - `sensitivity`: 10%
  - `anomaly`: 10%
- **Explainability Guarantee**: Every score update returns a `reasons` array documenting exactly which factors contributed points.

### 4.4. Security State Machine (`src/sentinel/state-machine.ts`)
Maintains server and tool security state across 5 stages:

$$\text{NORMAL (0–25)} \longrightarrow \text{MONITOR (26–50)} \longrightarrow \text{RESTRICT (51–75)} \longrightarrow \text{HUMAN\_APPROVAL (76–90)} \longrightarrow \text{QUARANTINE (91–100)}$$

- **Hysteresis**: Escalations occur immediately to safeguard the agent. De-escalation requires satisfying cooldown timers and score margins to eliminate flapping.

### 4.5. Quarantine Manager (`src/sentinel/quarantine.ts`)
Enforces server containment:
- Immediately flags server trust status as `QUARANTINED`.
- Blocks all subsequent tool calls via pre-execution interceptor.
- Stores forensic evidence record (`quarantineHistory`).
- Provides a controlled recovery endpoint (`recoverServer`). When recovered by an administrator, the server transitions to `MONITOR` (never directly to `NORMAL`).

### 4.6. Authentication & RBAC (`src/sentinel/auth.ts`)
- Role tiers: `viewer`, `analyst`, `incident_responder`, `admin`.
- Architecture designed for Keycloak / OIDC JWT validation with dev-mode bearer token support (`Bearer dev:<user>:<role>`).
- **Just-In-Time (JIT) Temporary Grants**: Allows granting emergency capability elevation with automatic expiration after $N$ seconds.

### 4.7. Glassmorphic Dashboard & REST APIs (`src/dashboard/`)
- HTTP REST API server exposing endpoints:
  - `GET /api/sentinel/state`
  - `GET /api/sentinel/servers`
  - `GET /api/sentinel/tools`
  - `GET /api/sentinel/events`
  - `GET /api/sentinel/approvals`
  - `POST /api/sentinel/servers/:id/quarantine`
  - `POST /api/sentinel/servers/:id/recover`
  - `POST /api/sentinel/trigger-malicious`
- Cyber-dark interface built with Vanilla CSS glassmorphism, responsive status banners, real-time risk gauges, and explainable decision cards.
