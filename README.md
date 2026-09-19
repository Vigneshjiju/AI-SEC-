# MCP-Sentinel: Adaptive Security Control Plane for Model Context Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-brightgreen)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-51%20passing-brightgreen)](https://vitest.dev)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](https://www.typescriptlang.org)

> **MCP-Sentinel sits between AI agents / MCP clients and MCP upstream servers to provide runtime behavioral observation, explainable risk scoring, dynamic security state enforcement, and automated quarantine.**

---

## Attribution & Foundation

**MCP-Sentinel** is built on top of [Niraven/mcp-gateway](https://github.com/Niraven/mcp-gateway) (licensed under MIT). 

We preserve and build upon `mcp-gateway`'s excellent MCP proxy foundations:
- MCP STDIO client/server proxy protocol implementation
- Static tool description scanning & poisoning detection
- Cryptographic descriptor hashing & baseline drift detection
- Token-bucket rate limiting
- Human approval gate mechanics
- Audit logging & JSONL run reporting

Around this foundation, **MCP-Sentinel adds an adaptive security control plane**:
- **Declared vs. Authorized vs. Observed Capability Model**
- **Runtime Tool Behavior Fingerprinting & Drift Detection**
- **Deterministic, Explainable Weighted Risk Engine (0–100)**
- **5-State Security State Machine (NORMAL → MONITOR → RESTRICT → HUMAN_APPROVAL → QUARANTINE)** with hysteresis and cooldown
- **Automated Quarantine & Controlled Recovery System**
- **Role-Based Access Control (RBAC) & Just-In-Time (JIT) Temporary Grants** (Keycloak-ready)
- **Live Glassmorphic Cybersecurity Dashboard** with real-time risk dials and explainable decisions
- **End-to-End Rug-Pull Attack Simulation & Verification Pipeline**

---

## The Problem: The "Rug-Pull" Attack in MCP

In the Model Context Protocol (MCP) ecosystem:
1. **Initial Trust Is Misleading**: A tool may declare benign intent (`search_logs`) and behave properly during testing or registration.
2. **Dynamic Behavior Drift**: Once deployed into production, an external MCP server can dynamically change behavior (a *rug-pull* attack), reading local files (`.env`, `~/.ssh/id_rsa`), extracting environment variables, or establishing unauthorized outbound network connections to Command & Control (C2) servers.
3. **Static Scanners Fail**: Static descriptor scanners and schema validators only inspect metadata *before* execution. They cannot see what happens *during* tool execution.
4. **LLM Is Not a Security Authority**: The AI agent cannot be trusted to self-police or detect subtle exfiltration channels embedded in tool outputs.

### The MCP-Sentinel Solution

MCP-Sentinel implements the closed-loop security control cycle:

```
      AI Agent / MCP Client
                │
                ▼
┌───────────────────────────────────────┐
│       MCP-Sentinel Gateway            │
│  Validate ↓ Observe ↓ Assess Risk ↓   │
│  Apply Policy ↓ Control ↓ Observe ↺   │
└───────────────────┬───────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
  Legitimate MCP          Third-Party Vendor
     Servers             Tools (Under Watch)
```

---

## Key Innovations

### 1. Capability Triad: Declared vs. Authorized vs. Observed
Every tool registration defines what it claims to do (`declaredCapabilities`) and what policies permit (`authorizedCapabilities`). During runtime, the `BehaviorEngine` tracks actual execution (`observedCapabilities`). Any mismatch dynamically contributes to the tool's risk score.

### 2. Explainable Deterministic Risk Engine (0–100)
Risk is never a black-box machine learning guess. Every risk score is calculated deterministically from concrete security factors:
$$\text{Risk Score} = \sum (\text{Factor Weight} \times \text{Observed Severity})$$
- **Integrity Risk**: Descriptor changes and schema modifications
- **Behavior Risk**: New filesystem, network, process, or environment access
- **Runtime Risk**: Capability firewall violations
- **Authorization Risk**: Role-permission mismatches
- **Sensitivity Risk**: Access to `.env`, private keys, cloud credentials
- **Anomaly Risk**: Prior incident history and abnormal response patterns

### 3. Adaptive State Machine
System and server trust states transition across 5 levels:
$$\text{NORMAL} \longrightarrow \text{MONITOR} \longrightarrow \text{RESTRICT} \longrightarrow \text{HUMAN\_APPROVAL} \longrightarrow \text{QUARANTINE}$$
- **Hysteresis**: Upward escalations are immediate; downward recoveries require explicit cooldown and admin authorization.
- **Quarantine Guarantee**: Quarantined servers are blocked by **hard security rules**. They are never automatically returned to `NORMAL` state merely because a score drops.

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Niraven/mcp-gateway.git
cd mcp-gateway

# Install dependencies
npm install

# Build TypeScript to dist/
npm run build

# Run full test suite (51 tests passing)
npm test
```

### Run the Signature Rug-Pull Attack Demo

Execute the complete end-to-end hackathon demonstration:

```bash
npm run demo
```

You will witness:
1. Registration of legitimate and third-party vendor servers
2. Normal tool call execution (`ALLOW`, Risk: 0, State: `NORMAL`)
3. Activation of the rug-pull compromise on the vendor server
4. Detection of 11 behavioral drift findings (`.env` access, C2 network connections, shell exec)
5. Risk score escalation from 0 → 78/100
6. State machine transition: `NORMAL` → `MONITOR` → `QUARANTINE`
7. Subsequent malicious execution attempts immediately **BLOCKED** by hard quarantine policy
8. Controlled recovery by SecOps administrator back to `MONITOR` state

### Run Comparative Benchmark Evaluation

```bash
npm run evaluate
```

Compares **Raw MCP**, **Static Gateway**, and **MCP-Sentinel Adaptive Defense** across real execution metrics:

| Scenario | Legitimate Task | Attack Detected | Attack Blocked | Contained? | Security Overhead |
|---|---|---|---|---|---|
| **A: Raw MCP** | YES | NO (MISSED) | NO (BYPASS) | NO | 0.00 ms |
| **B: Static Gateway** | YES | NO (MISSED) | NO (BYPASS) | NO | ~0.5 ms |
| **C: MCP-Sentinel** | **YES** | **YES** | **YES** | **YES (QUAR)** | **~1.1 ms** |

---

## Starting the Gateway with Live Dashboard

```bash
# Start Gateway with Sentinel control plane and web dashboard
npx tsx src/cli.ts start -c mcp-sentinel.json -d -p 3100
```

Open your browser to:
**`http://localhost:3100`**

### Dashboard Highlights
- **Giant Security State Banner**: Real-time glow indicators for system state (`NORMAL` through `QUARANTINE`).
- **Capability Mismatch Highlighting**: Real-time tags highlight unauthorized filesystem, network, or env accesses with pulsing alerts.
- **Explainable Security Decisions Card**: Detailed breakdowns answering *WHAT*, *WHY*, *EVIDENCE*, *POLICY*, and *ACTION*.
- **Interactive Demo Controls**: Buttons to trigger or reset the rug-pull attack live directly from the UI.
- **Human Approval Modal**: Review and approve/deny elevated-risk actions.

---

## Architecture & File Structure

```
src/
├── sentinel/                      # NEW MCP-Sentinel Control Plane Modules
│   ├── adaptive-controller.ts     # Central orchestrator (Validate→Observe→Assess→Control)
│   ├── auth.ts                    # RBAC, Keycloak-ready identity & JIT temporary grants
│   ├── behavior.ts                # Fingerprinting & runtime behavior drift engine
│   ├── events.ts                  # Pub/sub structured security event bus
│   ├── output-scanner.ts          # Prompt injection & secret leakage inspection
│   ├── policy.ts                  # Hard security rules + adaptive state-based policies
│   ├── quarantine.ts              # Server quarantine manager & controlled recovery
│   ├── registry.ts                # Metadata registry for servers & tools
│   ├── risk-engine.ts             # Deterministic weighted risk scoring (0–100)
│   ├── runtime.ts                 # Runtime capability firewall
│   ├── state-machine.ts           # 5-state adaptive state machine with hysteresis
│   └── types.ts                   # Core TypeScript type definitions
├── proxy/
│   └── gateway.ts                 # Extended MCP Proxy integrating Sentinel pipeline
├── dashboard/
│   ├── index.html                 # Redesigned glassmorphic dark-theme security dashboard
│   └── server.ts                  # REST API server for dashboard telemetry & actions
├── middleware/                    # PRESERVED Niraven Gateway Middlewares
│   ├── approval.ts                # Approval gate middleware
│   ├── audit-logger.ts            # JSONL audit logging
│   ├── rate-limiter.ts            # Token bucket rate limiting
│   └── security-scanner.ts        # Descriptor poisoning & prompt injection scanner
├── reporting/                     # Run report generator & secret redaction
└── cli.ts                         # Command-line interface
test/
├── fixtures/
│   ├── legitimate-server.mjs      # Server A: SOC Tools (Benign)
│   ├── rugpull-server.mjs         # Server B: Rug-Pull Demo Server (Switches behavior)
│   └── high-risk-server.mjs       # Server C: High-Risk Tools (Requires approval)
├── demo.ts                        # End-to-end demo execution script
└── evaluation.ts                  # Real comparative evaluation benchmark script
```

---

## Security Scenarios Tested

Automated unit and integration test suite (`tests/sentinel.test.ts` & `tests/gateway.test.ts`):

1. **TEST 1: Normal Tool Invocation** → Result: `ALLOW` (Risk: 0, State: `NORMAL`)
2. **TEST 2: Unauthorized Tool Invocation** → Result: `BLOCK` (Hard authorization rule)
3. **TEST 3: Descriptor Modification** → Result: `DRIFT DETECTED` (Cryptographic hash mismatch)
4. **TEST 4: Tool Poisoning Payload** → Result: `DETECT` (Descriptor scanner catches injection)
5. **TEST 5: Unexpected Filesystem Access** → Result: `RISK INCREASE` (Undeclared paths detected)
6. **TEST 6: Unexpected Network Access** → Result: `RISK INCREASE / BLOCK` (Outbound C2 detected)
7. **TEST 7: Sensitive File Access** → Result: `RISK INCREASE` (`.env`, `id_rsa` flags triggered)
8. **TEST 8: Repeated Abnormal Calls** → Result: `RESTRICT` (Score escalation across calls)
9. **TEST 9: High-Risk Destructive Tool** → Result: `HUMAN APPROVAL` (`block_ip` paused for review)
10. **TEST 10: Severe Malicious Behavior** → Result: `QUARANTINE` (Immediate execution cutoff)
11. **TEST 11–15: Auth & JIT Grants** → Result: Role-based gating, JIT temporary grants, expiry cleanup

---

## Realistic Scope & Limitations

As an evidence-based security control plane, we state clearly what MCP-Sentinel provides and its current limitations:

- **What It Detects**: Output-reflected file paths, unauthorized outbound network requests, process execution indicators, environment variable access, and schema mismatches.
- **Defense in Depth, Not a Magic Bullet**: MCP-Sentinel analyzes tool responses and proxy traffic. In production, it is intended to be paired with OS-level sandbox isolation (e.g. gVisor, Docker containers, or eBPF syscall monitors) for defense-in-depth.
- **Explainability Over Black-Box Models**: We intentionally use deterministic weighted scoring rather than opaque neural networks so that every blocked action has an auditable evidence chain.

---

## License

MIT License. See [LICENSE](LICENSE) for details. MCP-Sentinel is built on the [Niraven/mcp-gateway](https://github.com/Niraven/mcp-gateway) repository with deep gratitude to the original authors.
