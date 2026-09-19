# MCP-Sentinel — Adaptive Security Control Plane for the Model Context Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-brightgreen)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-95%20passing-brightgreen)](https://vitest.dev)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](https://www.typescriptlang.org)

> An MCP server can behave perfectly during review and turn hostile afterwards.
> **MCP-Sentinel keeps watching after the contract is signed** — observing what tools
> actually do at runtime, scoring the divergence, and containing servers that drift.

---

## The problem

Everything that secures an MCP server today happens **before** it runs:

| Layer | When it checks | What it misses |
|---|---|---|
| Descriptor scanning | Registration | A tool that changes its descriptor later |
| Schema validation | Registration | Behaviour the schema never described |
| Human review | Onboarding | Literally everything after onboarding |
| Rate limiting | Per call | A single malicious call |

A third-party server passes every one of those, earns trust, then starts reading
`~/.ssh/id_rsa` and posting to a C2 endpoint. This is the **rug-pull**, and static
inspection is structurally incapable of seeing it.

Our evaluation reproduces it against a real MCP server:

| Architecture | Legit task | Detected | Blocked | Contained | Security overhead |
|---|---|---|---|---|---|
| **A** Raw MCP | ✅ | ❌ | ❌ | ❌ | 0 ms |
| **B** Static gateway | ✅ | ❌ | ❌ | ❌ | ~2.8 ms |
| **C** MCP-Sentinel | ✅ | **✅** | **✅** | **✅ quarantined** | ~10.8 ms |

Reproduce with `npm run evaluate` — the numbers are measured, not quoted.

---

## Quick start

```bash
npm install

# The interactive console — this is the demo
npm run console          # → http://localhost:3100

# Or run scenarios in the terminal
npm run demo             # the signature rug-pull
npm run demo:all         # all six scenarios
npm run evaluate         # the comparative benchmark

npm test                 # 95 tests, incl. 7 against real MCP child processes
```

Open the console and click a scenario. Each one **spawns real MCP server
processes** and drives genuine stdio JSON-RPC tool calls through the pipeline.
The risk scores, drift findings, state transitions and quarantines you watch
appear are computed from the bytes those servers actually return.

---

## The six scenarios

| Scenario | Technique | What it proves |
|---|---|---|
| **Benign investigation** | Control | No false positives on a textbook SOC workflow |
| **Rug-pull** | T1195.002 Supply Chain | Trust earned, then betrayed — caught at both the descriptor and runtime layers |
| **Exfiltration chain** | T1041 Exfil over C2 | Every tool is authorized; the *order* is the attack |
| **Prompt injection** | OWASP LLM01 | An honest server returning attacker-controlled data |
| **Hostile input** | SSRF / traversal / injection | Rejected before the child process is contacted |
| **Privilege escalation** | T1548 | Capability-tiered RBAC + time-boxed JIT elevation |

Each scenario declares its **expected outcome** and the engine verifies it —
`expectationsMet` is reported per run, so a broken control plane fails visibly
instead of quietly printing a success story.

---

## How it works

```
   AI agent / MCP client
            │  JSON-RPC over stdio
            ▼
┌───────────────────────────────────────────────────────────┐
│  MCP-SENTINEL                                             │
│                                                           │
│  PRE-EXECUTION                    POST-EXECUTION          │
│  ─────────────                    ──────────────          │
│  1 identity verification          6 behaviour fingerprint │
│  2 hard quarantine rule           7 baseline comparison   │
│  3 input validation               8 output scanning       │
│  4 capability lease               9 risk assessment       │
│  5 contextual sequence           10 state transition      │
│    · data-flow taint             11 quarantine / receipt  │
│    · capability-tiered RBAC                               │
│    · human approval gate                                  │
└───────────────────────────────┬───────────────────────────┘
                                ▼
                        MCP servers (untrusted)
```

### 1. The capability triad

| Layer | Source | Meaning |
|---|---|---|
| **Declared** | Inferred from the tool's own descriptor | What it says it does |
| **Authorized** | Policy | What it is permitted to do |
| **Observed** | Real tool responses at runtime | What it actually did |

Drift is `Observed ⊄ Declared`. A policy violation is `Observed ⊄ Authorized`.
Comparison is **semantic**, not string equality — a private-range address is not
external egress, and a declared scope of `*` means "declared, unconstrained".

### 2. Risk is persistent, not per-call

Risk carries forward, decays on a configurable half-life, and **compounds** when
bad behaviour repeats:

```
carried  = previous × 0.5 ^ (elapsed / halfLife)
score    = max(instant, carried) + instant × accumulation
```

This matters: with a stateless score, one innocuous response resets a compromised
server to zero. Every score ships with a `reasons[]` array naming each contributing
factor — no opaque model anywhere in the decision path.

### 3. Five-state machine with hysteresis

```
NORMAL → MONITOR → RESTRICT → HUMAN_APPROVAL → QUARANTINE
```

Escalation is immediate. De-escalation requires both a margin below the threshold
and a cooldown, so states cannot flap. **Quarantine is a hard rule** evaluated
before anything else — no risk arithmetic can unlock it, and recovery is an
operator action that lands in `MONITOR`, never straight back to `NORMAL`.

### 4. Capability-tiered RBAC

Roles are granted **capability classes**, not lists of tool names — so policy
covers servers whose tools nobody enumerated in advance:

| Role | READ | EXTERNAL_LOOKUP | WRITE | INFRA_CONTROL | SECRET_ACCESS | DATA_TRANSFER | EXEC |
|---|---|---|---|---|---|---|---|
| viewer | ✅ | ✅ | | | | | |
| analyst | ✅ | ✅ | ✅ | | | | |
| incident_responder | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Just-In-Time grants elevate a user for a bounded TTL and can target either a tool
name or a whole capability class.

### 5. Approvals that actually resume

Approving a request issues a **single-use, time-boxed grant**. The retried call
redeems it and proceeds. Without this, approval only flips a status field and the
agent loops forever re-requesting the same action.

---

## The console

`npm run console` serves a live operations view at `http://localhost:3100`:

- **Attack console** — launch any scenario; steps stream in over Server-Sent Events
- **Kill chain** — every step with its narrative, verdict, evidence and real tool output
- **Risk timeline** — multi-series chart with threshold guides and a hover crosshair
- **Capability triad** — declared vs authorized vs observed, violations highlighted
- **Explained decisions** — what / why / evidence / policy / action for every restriction
- **Approvals** — approve or deny; the grant is issued immediately
- **Receipts** — SHA-256 hashed, tamper-evident decision ledger

It is a single self-contained HTML file: no CDN fonts, no external scripts, and all
untrusted text is escaped before rendering — the console reads output from servers
it assumes are hostile.

---

## Architecture

```
src/
├── sentinel/
│   ├── adaptive-controller.ts   Orchestrator: pre/post execution pipeline
│   ├── scenario-engine.ts       Drives real MCP servers through live scenarios
│   ├── capability-model.ts      Shared tool classification + capability-tier RBAC
│   ├── behavior.ts              Fingerprinting, drift detection, conformance
│   ├── risk-engine.ts           Stateful, decaying, explainable 0–100 scoring
│   ├── state-machine.ts         5-state machine with hysteresis
│   ├── policy.ts                Hard rules, adaptive policy, approval grants
│   ├── auth.ts                  RBAC + JIT grants
│   ├── contextual-engine.ts     Capability-transition / sequence analysis
│   ├── data-flow.ts             Taint tracking for sensitive data
│   ├── semantic-firewall.ts     Detects tool-contract expansion
│   ├── identity.ts              HMAC token verification
│   ├── lease-manager.ts         Time-bounded capability leases
│   ├── input-validator.ts       SSRF / traversal / command injection
│   ├── output-scanner.ts        Prompt injection + secret leakage
│   ├── quarantine.ts            Containment and controlled recovery
│   ├── receipts.ts              SHA-256 decision ledger
│   └── registry.ts              Server/tool registry + capability inference
├── proxy/gateway.ts             MCP stdio proxy with the Sentinel pipeline inline
├── dashboard/                   SSE server + self-contained console
├── middleware/                  Rate limiting, approval gate, scanner, audit log
└── cli.ts                       start · console · scan · report · validate · init
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for subsystem detail and
[THREAT_MODEL.md](THREAT_MODEL.md) for what is and is not in scope.

---

## Using it as a real gateway

```bash
npx tsx src/cli.ts start -c mcp-sentinel.json -d -p 3100
```

Point an MCP client at the gateway instead of at your servers. It proxies
`tools/list` and `tools/call` over stdio, applying the full pipeline to each call.

Audit your existing setup without running anything:

```bash
npx tsx src/cli.ts scan --claude-desktop
npx tsx src/cli.ts scan --claude-desktop --fix > hardened.json
```

---

## Scope and honest limitations

**What it observes.** Sentinel analyses MCP protocol traffic: tool descriptors,
arguments, and response content. That is a real and load-bearing signal — it is
where exfiltrated data, C2 URLs, file paths and injected instructions actually
appear — but it is **evidence of behaviour, not syscall-level ground truth**.

**What it cannot see.** A server that exfiltrates over a side channel without
reflecting anything in its MCP response is invisible to this layer. Sentinel is
designed to be paired with OS-level isolation (containers, gVisor, eBPF syscall
monitoring) for defence in depth. It narrows the window; it does not close it.

**Why deterministic scoring.** Every block is explainable and reproducible. An LLM
judging its own tool calls is not a security boundary, and an opaque model score
cannot be audited after an incident.

**Prompt injection.** The output scanner detects known patterns. Pattern matching
does not solve prompt injection — the durable mitigation here is the authorization
boundary: in the injection scenario the agent is *successfully* injected and still
cannot reach the credentials, because its role holds no `SECRET_ACCESS` capability.

---

## Attribution

Built on [Niraven/mcp-gateway](https://github.com/Niraven/mcp-gateway) (MIT), which
contributes the MCP stdio proxy, descriptor scanning and hashing, token-bucket rate
limiting, the approval gate, and JSONL audit logging. MCP-Sentinel adds the adaptive
control plane described above.

## License

MIT — see [LICENSE](LICENSE).
