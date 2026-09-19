# MCP-Sentinel: Demonstration Guide

This guide details the step-by-step execution of the signature MCP-Sentinel demonstration: **Trusted Tool → Rug-Pull Attack → Drift Detection → Risk Escalation → Adaptive Control → Quarantine → Controlled Recovery**.

---

## Prerequisites

Ensure dependencies are installed and the codebase is compiled:

```bash
cd e:/AI-SEC/mcp-gateway
npm install
npm run build
```

---

## Demo Option 1: Automated End-to-End CLI Demo

Run the automated demonstration script:

```bash
npm run demo
```

### What You Will See:

```
══════════════════════════════════════════════════════════════════════════════
  🛡️  MCP-SENTINEL: ADAPTIVE SECURITY CONTROL PLANE FOR MCP
     Live Rug-Pull Attack Detection & Adaptive Control Plane Verification
══════════════════════════════════════════════════════════════════════════════

STEP 1: Initializing MCP-Sentinel Gateway with Upstream Servers
  ✓ Sentinel Gateway instantiated with adaptive security control plane
  ✓ Policy Engine: RBAC + State-based rules loaded
  ✓ Behavior Engine: Fingerprint comparison enabled
  ✓ Risk Engine: Weighted deterministic assessment active
  ✓ Live Security Dashboard available at: http://localhost:3100

STEP 2: Registering Servers & Baselines (Declared Capabilities)
  Declared Capabilities for rugpull-vendor/search_logs:
    - Filesystem: ["logs/"]
    - Network: none (internal only)
    - Process Execution: false
    - Env Variable Access: false
    - Sensitive Files Access: false
  ✓ Initial Trust Status: TRUSTED | Security State: NORMAL | Risk Score: 0/100

STEP 3: Tool Call 1 — Normal Execution (Trusted Baseline Established)
  AI Agent executes: rugpull-vendor__search_logs({ query: "authentication" })
  Pre-Execution Check:  ALLOW  (Reason: Tool call permitted by policy)
  Post-Execution Analysis:
    - Behavioral Drift Findings: 0 (Expected: 0)
    - Evaluated Risk Score: 0/100
    - Current Security State: NORMAL
  ✓ Result: Clean execution conformant with baseline.

STEP 4: ⚡ TRIGGERING RUG-PULL ATTACK ON VENDOR SERVER ⚡
  Simulating Compromise: Server switches to malicious behavior.
  The tool now exfiltrates credentials, reads sensitive files, and contacts external C2 server.
  Vendor server payload mode: MALICIOUS_MODE = true

STEP 5: Tool Call 2 — Behavioral Drift Detected (Stage 1: RESTRICT)
  AI Agent executes: rugpull-vendor__search_logs({ query: "system_logs" })
  Pre-Execution Check:  ALLOW  (Initial state allows call under observation)
  ⚠️ Behavioral Drift Findings Detected (5):
    • [BEHAVIOR_DRIFT] Behavioral drift detected: 4 finding(s) (severity: critical)
    • [NEW_FILESYSTEM_ACCESS] Tool accessed 5 previously unseen filesystem path(s) (severity: high)
    • [NEW_EXTERNAL_NETWORK] Tool contacted 1 previously unseen network destination(s) (severity: high)
    • [NEW_EXTERNAL_NETWORK] Tool initiated an external network connection not seen in baseline (severity: critical)
    • [CAPABILITY_MISMATCH] Observed capability exceeds authorized capability: external network access (severity: critical)
  Dynamic Risk Engine Assessment:
    - New Risk Score: 49/100
    - Primary Contributing Factors:
        behavior        : +30 points
        runtime         : +7 points
        authorization   : +12 points
  State Machine Transition:
    - State Shift: NORMAL ──►  MONITOR 
    - Trust Status: SUSPICIOUS

STEP 6: Tool Call 3 — Critical Exploitation & Auto-Quarantine Trigger
  AI Agent attempts another call; vendor tool attempts full credential exfiltration and shell execution...
  Risk Escalation:
    - Escalated Risk Score:  78/100 
    - State Machine Transition: MONITOR ──►  QUARANTINE 
    - Auto-Quarantine Triggered: SERVER QUARANTINED (Risk >= 75)

STEP 7: Tool Call 4 — Hard Security Rule Verification (Call Blocked)
  AI Agent attempts subsequent execution on quarantined server...
  Pre-Execution Check Result:
    - Action:  BLOCK 
    - Reason: Server "rugpull-vendor" is quarantined
    - Applied Policy: hard-quarantine (Hard Rule: true)
    - Result: ✓ All calls successfully blocked. Zero execution permitted.

STEP 8: Explainable Security Decision Audit
  Sentinel Decision Record:
    1. WHAT HAPPENED?     Third-party tool exhibited sudden behavior divergence
    2. WHY DID IT REACT?  Observed capabilities (.env, C2 network, command exec) violated declared profile
    3. WHICH EVIDENCE?    5 runtime drift findings with cryptographic baseline mismatch
    4. WHAT POLICY?       Adaptive State Machine + Hard Quarantine Policy
    5. WHAT ACTION TAKEN? Server quarantined; execution blocked; operator alerted

STEP 9: Controlled Operator Recovery Flow
  Demonstrating controlled recovery by Security Administrator:
  Action: SecOps admin approves reset and enters containment review.
  - Recovery Executed: SUCCESS
  - New Security State: MONITOR (Recovered to MONITOR, never straight to NORMAL!)
  - Hard Rules: Future operations remain under elevated telemetry until re-certified.
```

---

## Demo Option 2: Live Interactive Web Dashboard

To experience the live glassmorphic security dashboard and trigger attacks interactively:

```bash
# Run demo with dashboard server kept active:
npm run demo -- --serve
```

Or start the standalone gateway with dashboard enabled:

```bash
npx tsx src/cli.ts start -c mcp-sentinel.json -d -p 3100
```

### Interactive Steps on Dashboard:

1. Open **`http://localhost:3100`** in your browser.
2. Note the initial **NORMAL (Green)** system status and zero risk index.
3. Click the **"🔥 Trigger Rug-Pull Malicious Mode"** button in the purple demo simulation bar.
4. Watch the top banner instantly switch to **CRITICAL: Server Quarantined** as risk reaches 78/100.
5. In the **"Tool Capabilities & Drift"** tab:
   - Observe red highlighted tags for unauthorized capabilities (`external_net`, `env_access`, `sensitive_files`).
   - Notice the status badge switches to **DRIFT DETECTED**.
6. Switch to the **"Explainable Decisions"** tab:
   - View the forensic card breaking down WHAT happened, WHY Sentinel reacted, WHICH evidence was flagged, and WHAT policy was applied.
7. Click **"Recover"** on the quarantined server in the MCP Servers tab to observe controlled recovery to **MONITOR** state.
