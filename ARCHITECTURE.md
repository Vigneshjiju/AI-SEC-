# MCP-Sentinel — Architecture

## 1. Position in the stack

MCP-Sentinel is an in-line control plane between an AI agent (or MCP client) and
the MCP servers it calls. It speaks MCP on both sides, so it is transparent to
clients: point the client at the gateway instead of at the servers.

```
                      ┌──────────────────────┐
                      │  AI agent / client   │
                      └──────────┬───────────┘
                                 │ JSON-RPC (stdio)
                                 ▼
┌────────────────────────────────────────────────────────────────┐
│                       MCP-SENTINEL                             │
│                                                                │
│  PRE-EXECUTION                     POST-EXECUTION              │
│  ──────────────                    ───────────────             │
│  1  Identity verification          6  Behaviour fingerprint    │
│  2  Hard quarantine rule           7  Baseline comparison      │
│  3  Input validation               8  Runtime guard + output   │
│  4  Capability lease               9  Risk assessment          │
│  5  Contextual sequence           10  State transition         │
│       · data-flow taint           11  Quarantine, lease revoke │
│       · capability-tier RBAC      12  Decision receipt         │
│       · approval gate                                          │
└────────────────────────────────┬───────────────────────────────┘
                                 ▼
                      ┌──────────────────────┐
                      │  MCP servers         │
                      │  (assumed hostile)   │
                      └──────────────────────┘
```

The decisive property is that **6–12 run after the response comes back**. Every
other MCP security layer stops at step 5.

---

## 2. The capability triad

| Layer | Stored in | Derived from |
|---|---|---|
| **Declared** | `ToolRegistration.declaredCapabilities` | Inferred from the tool's own descriptor (`inferDeclaredCapabilities`) |
| **Authorized** | `ToolRegistration.authorizedCapabilities` | Starts as a copy of declared; narrowed by policy |
| **Observed** | `ToolRegistration.currentFingerprint` | Extracted from real tool responses |

- `Observed ⊄ Declared` → **behavioural drift**, contributes risk
- `Observed ⊄ Authorized` → **capability violation**, contributes risk and can block

### Why inference matters

Registering a tool with an empty declared set makes the comparison meaningless —
every legitimate URL in any response becomes a "violation". Reading the declaration
out of the descriptor is what makes declared-vs-observed a real comparison.

### Semantic comparison

`BehaviorEngine.assessConformance` compares meaning, not strings:

- private/loopback/link-local destinations are **not** external egress
- a declared scope of `*` means "declared, unconstrained"
- a declared host allowlist is matched by containment, not equality
- sensitive paths are violations whenever `sensitiveFileAccess` is unauthorized

---

## 3. Risk engine

Instantaneous score from the current observation:

```
instant = Σ (factorᵢ)  bounded [0,100]

integrity     descriptor change, missing baseline
behavior      drift findings, weighted by type
runtime       capability-firewall violations
authorization role mismatch, capability mismatch
sensitivity   sensitive file / env access
anomaly       prior incidents, output anomalies, frequency
```

Blended with persistent state:

```
carried = previous × 0.5 ^ (elapsed / halfLifeMs)
score   = min(100, max(instant, carried) + instant × accumulation)
```

**Defaults**: `halfLifeMs` 120 000, `accumulation` 0.35.

Three consequences that matter:

1. A compromised server cannot clear itself by returning one clean response.
2. Repeated hostile behaviour compounds into quarantine rather than plateauing.
3. Genuinely reformed behaviour decays back to zero without operator toil.

Every assessment returns `reasons[]` naming each contributing factor, including
carried risk and compounding, so a score is always auditable.

---

## 4. Security state machine

```
NORMAL(0–25) → MONITOR(26–50) → RESTRICT(51–75) → HUMAN_APPROVAL(76–90) → QUARANTINE(91+)
```

Thresholds are configurable. Behaviour:

- **Escalation** applies immediately — security takes priority over stability.
- **De-escalation** requires being below the current threshold by `margin` *and*
  having spent `cooldownMs` in the state. This is what prevents flapping.
- **Quarantine** is enforced by a hard rule checked before risk is consulted at all.
  Recovery is an operator action that lands in `MONITOR`.

---

## 5. Authorization

`capability-model.ts` is the single source of truth for "what class of thing does
this tool do", used by **both** the RBAC layer and the sequence analyser — so a tool
is never classified one way for authorization and another way for context.

Resolution order for a tool: explicit profile → name heuristic → description
heuristic → `UNKNOWN` (gated at the analyst tier, never treated as harmless).

Authorization resolves most-specific-first:

1. Admin / wildcard
2. Active JIT grant (by tool name **or** capability class)
3. Explicit named role permission
4. Capability-tier permission

Step 4 is what lets policy cover third-party servers whose tool names were never
enumerated — the normal case for an MCP gateway.

---

## 6. Contextual sequence analysis

Answers: *is this action reasonable given what this workflow has already done?*

Dangerous patterns:

| Pattern | Verdict |
|---|---|
| recon → SECRET_ACCESS → DATA_TRANSFER | **block** (ATT&CK exfiltration) |
| recon → DATA_TRANSFER without incident logging | **block** |
| SECRET_ACCESS → INFRASTRUCTURE_CONTROL | **block** |
| recon → SECRET_ACCESS | **require approval** (plausible mid-incident) |
| READ → EXTERNAL_LOOKUP → WRITE | **allow** (conformant investigation) |

The distinction is deliberate: escalate the suspicious-but-plausible step to a
human; hard-block the irreversible one.

---

## 7. Approvals

`PolicyEngine.approveRequest` issues a **single-use, time-boxed grant** keyed by
`serverId::tool::userId`. The next matching call redeems it via
`consumeApprovalGrant` and proceeds under policy `approval-granted`.

Without the grant, approval only mutates a status field: the agent retries, hits
the same rule, and opens another request — an infinite loop. The grant is consumed
on redemption, so approval authorizes one action, not a standing permission.

---

## 8. Scenario engine

`scenario-engine.ts` drives end-to-end scenarios against real MCP servers:

- spawns fixtures as child processes over `StdioClientTransport`
- registers servers and tools from the **actual** `tools/list` response
- for each step: `preExecute` → real `tools/call` → `postExecute`
- re-reads descriptors on demand and runs the Semantic Change Firewall over diffs
- supports operator steps: recovery, JIT grants, approvals, revalidation
- streams `ScenarioStepResult` to subscribers (the console consumes these via SSE)
- verifies each step against the scenario's declared expectation

Because every step carries an expectation, a regression in the control plane makes
scenarios **fail visibly** rather than silently printing a success narrative.

---

## 9. Dashboard

`dashboard/server.ts` exposes:

| Endpoint | Purpose |
|---|---|
| `GET /api/sentinel/stream` | SSE: security events, scenario steps, overview |
| `GET /api/sentinel/scenarios` | Scenario catalogue |
| `POST /api/sentinel/scenarios/:id/run` | Launch (202, progress over SSE) |
| `POST /api/sentinel/scenarios/reset` | Clean baseline |
| `GET /api/sentinel/{state,servers,tools,events,timeline,receipts,approvals,leases,grants,workflows}` | Telemetry |
| `POST /api/sentinel/servers/:id/{quarantine,recover}` | Containment |
| `POST /api/sentinel/approvals/:id/{approve,deny}` | Approval decisions |

Presentation shaping happens server-side so the console stays a pure view. The
console is one self-contained HTML file — no external fonts or scripts — and
escapes all untrusted text before rendering, since tool output originates from
servers the system explicitly assumes are hostile.

---

## 10. Trust boundaries

| Boundary | Assumption |
|---|---|
| MCP client → gateway | Authenticated; role claims verified, never taken on trust |
| Gateway → MCP server | **Fully untrusted** — descriptors, arguments and responses are all adversarial input |
| Tool response → risk engine | Untrusted data, parsed defensively |
| Dashboard → control plane | Operator-authenticated in deployment; local-only by default |

See [THREAT_MODEL.md](THREAT_MODEL.md) for what this design does and does not cover.
