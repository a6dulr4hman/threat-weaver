<div align="center">

# 🛡️ ThreatWeaver

### Autonomous DevSecOps Engine

**ThreatWeaver is an AI-driven offensive-security platform that autonomously discovers, exploits, verifies, and patches web-application vulnerabilities — then writes you the report.**

It pairs a live black-box attack engine (DAST) with the **K2-Think-v2** reasoning model running a continuous ReAct loop, and renders the whole thing as a real-time, animated attack graph in a Vercel-style dashboard.

</div>

---

## Table of Contents

1. [What is ThreatWeaver?](#what-is-threatweaver)
2. [Key Features](#key-features)
3. [How It Works — The Autonomous Pipeline](#how-it-works--the-autonomous-pipeline)
4. [The K2-Think-v2 Agent](#the-k2-think-v2-agent)
5. [The Agent Toolbox](#the-agent-toolbox)
6. [Vulnerability Correlation Engine](#vulnerability-correlation-engine)
7. [Authentication & Account Model (Clerk)](#authentication--account-model-clerk)
8. [Domain Verification](#domain-verification)
9. [The Live Dashboard](#the-live-dashboard)
10. [Architecture & Tech Stack](#architecture--tech-stack)
11. [Project Structure](#project-structure)
12. [Data Model](#data-model)
13. [HTTP API Reference](#http-api-reference)
14. [Setup & Installation](#setup--installation)
15. [Environment Variables](#environment-variables)
16. [The Demo Target — Nimbus CRM](#the-demo-target--nimbus-crm)
17. [Configuration & Safety Limits](#configuration--safety-limits)
18. [Testing](#testing)
19. [Security Considerations](#security-considerations)
20. [Reports](#reports)
21. [Glossary](#glossary)

---

## What is ThreatWeaver?

ThreatWeaver automates the full offensive-to-defensive security loop that a human red-team + blue-team would normally perform by hand:

- **Recon** — fingerprints the target's open ports and service versions.
- **Discovery & Exploitation (DAST)** — probes the live application with crafted HTTP payloads, adapting each request based on the previous response.
- **Verification** — reproduces confirmed exploits inside a sandboxed Python subprocess (proof-of-concept).
- **Remediation** — generates human-reviewable patch code for every confirmed flaw.
- **Assessment & Reporting** — produces a CISO-ready severity verdict and a downloadable PDF report.

The whole process is **driven by the LLM itself**, not a fixed script. The platform exposes a set of tools; the K2-Think-v2 model decides which tool to call next, reads the raw result, reasons about it, and engineers the next move — exactly like a human pentester at a terminal.

> ⚠️ **Authorized use only.** ThreatWeaver performs real, active exploitation against the target you point it at. You must own the domain (enforced via DNS verification) and only scan systems you are authorized to test.

---

## Key Features

| Feature | Description |
|---|---|
| 🤖 **Autonomous agent** | K2-Think-v2 drives a ReAct (Reason + Act) loop — no hard-coded attack playbook. |
| 🌐 **Live DAST** | Raw, sequential HTTP exploitation with a persistent cookie jar (handles auth flows). |
| 🔎 **Recon + CVE lookup** | `nmap` service/version detection, then CVE research via web search. |
| 🧪 **Sandboxed PoC** | Confirms crash/error-based findings in an isolated `python3` subprocess. |
| 🩹 **AI remediation** | Generates patch code + description + CVE refs for each confirmed vulnerability. |
| 🧬 **Correlation engine** | De-duplicates findings ↔ PoCs ↔ patches into one canonical vuln each (detected = tested = remediated). |
| 📊 **Real-time attack graph** | Animated canvas node graph (recon → scan → detection → PoC → patch) that updates live with no page reload. |
| ⏱️ **Scan timer + token counter** | Live duration timer and full K2-Think-v2 token accounting (reasoning + patches + assessment). |
| 📄 **PDF reports** | Downloadable vulnerability report with severity, findings, and full remediation code. |
| 🔐 **Clerk auth** | Per-account workspace ownership — only you can scan domains you registered. |
| ✅ **Domain verification** | Cloudflare DNS-over-HTTPS TXT-record ownership check (with HTTP fallback). |

---

## How It Works — The Autonomous Pipeline

ThreatWeaver runs as a **Finite State Machine (FSM)** wrapping the K2 agentic loop. A job advances through these phases (`FSMState`):

```
ready ──▶ recon ──▶ dast_testing ──▶ poc_verification ──▶ blue_team_remediation ──▶ complete
```

| Phase | What happens |
|---|---|
| **`ready`** | Job created against a verified workspace; awaiting start. |
| **`recon`** | `run_nmap` fingerprints open ports + service versions; `internet_search` looks up CVEs for any versioned service. |
| **`dast_testing`** | The agent probes the live app with `send_http_request` / `run_fuzzer`, reading each response and crafting the next payload. |
| **`poc_verification`** | Crash/error-based findings are reproduced in a sandbox with `execute_safe_poc`. (Success-based exploits like auth bypass are self-confirming.) |
| **`blue_team_remediation`** | `generate_patch` produces remediation code for each confirmed vulnerability. |
| **`complete`** | Findings are correlated, K2 writes the final assessment, severity is scored, and the PDF report is generated. |

### Important nuance: `status` vs `pipeline_phase`

- `job.status` is the FSM's internal state (can flip to `complete` internally before the report exists).
- `job.pipeline_phase` is a **high-water mark** only advanced to `complete` **after** `_finalize_and_report()` actually finishes (report generated + `completed_at` stamped).

The dashboard treats a job as *truly done* only when **`status == complete` AND `report` exists AND `completed_at` is set** — this prevents the UI from showing "Complete" while the scan is still hunting for more vulnerabilities.

### The outer driver

`run_cycle()` runs the inner agentic loop up to `MAX_ITERATIONS` steps. The jobs router re-runs `run_cycle()` a few times in case a cycle exits early without reaching `COMPLETE` (e.g. a transient JSON parse error). On **any** loop exit (complete, error, timeout, max-iterations, exception) the orchestrator **always finalizes** — guaranteeing a severity score and a report are produced.

---

## The K2-Think-v2 Agent

The cognitive core lives in [`app/services/k2_agent.py`](app/services/k2_agent.py). Each iteration:

1. **State hydration** — the orchestrator serializes the current world state (target, source-derived route map, coverage checklist, prior attempts, exhausted endpoints, iteration counter) into JSON.
2. **Reason** — K2 thinks inside `<think>...</think>` tags (Chain-of-Thought).
3. **Decide** — the reply MUST end with exactly one JSON object:
   ```json
   {"action": "tool_call", "tool": "send_http_request", "arguments": { ... }, "reasoning": "one sentence"}
   ```
   or
   ```json
   {"action": "complete", "summary": "what was found and fixed"}
   ```
4. **Act** — the platform executes the chosen tool and feeds the raw result back into the conversation.
5. **Repeat** until the agent finishes or a guardrail trips.

### Reasoning principles baked into the system prompt

- **Route map is authoritative** — the agent works a source-derived coverage checklist, not just links it sees in HTML (admin tools, lookup views, and report builders often exist *only* in source).
- **Success is also a finding** — most real exploits return `200 OK`: an injected login that returns an authenticated page is an **auth bypass**; a file param that returns `root:x:0:0:` is **path traversal**; a host param that returns `uid=0(root)` is **command injection**.
- **Classify by observed trigger** — a `500` from a `'` is SQLi, not XSS. Findings are labeled by the exact input that broke them and the exact behaviour seen.
- **No hallucinated patches** — `generate_patch` is only allowed after a directly-observed signal (`is_server_error`, `server_crash_suspected`, `exploit_confirmed`, or observed successful exploitation). A service name/version alone never justifies a patch.
- **Persistent session** — a single cookie jar persists across all requests in a job, so the agent can log in (form-encoded) and then probe authenticated routes.

### Resilience

K2 is a reasoning model that occasionally emits prose around its JSON. `decide()` retries up to `MAX_PARSE_RETRIES` (2) times with a corrective nudge, and a rolling conversation window (`MAX_HISTORY_MESSAGES` = 30) keeps the context under the token budget.

---

## The Agent Toolbox

All tools are dispatched by the MCP client ([`app/services/mcp_client.py`](app/services/mcp_client.py)):

| Tool | Purpose | Key behaviour |
|---|---|---|
| **`run_nmap`** | Recon | `nmap -sV` service/version detection (light probes, aggressive timing, 90s host timeout). Returns `[{protocol, port, state, service, version}]`. Degrades gracefully if `nmap` isn't installed. |
| **`send_http_request`** | Primary weapon | Raw single HTTP request (GET/POST/PUT/PATCH/DELETE/…). Supports `json_body` *and* `form_data`. Flags `is_server_error`, `stack_trace_detected`, and `server_crash_suspected` (a dropped connection = likely backend crash). Persistent cookie jar. Body capped at 12 000 chars to protect the context window. |
| **`run_fuzzer`** | Batch probing | Sends a matrix of payloads, measures status/length/timing, flags 5xx and crash-signal transport errors as anomalies. |
| **`internet_search`** | CVE lookup | Researches known CVEs for a `component` + `version` via the **Brave Web Search API** (reads `BRAVE_SEARCH_API_KEY`). Returns reference URLs/titles/descriptions. |
| **`execute_safe_poc`** | Verification | Runs an agent-authored Python script in an isolated `python3` subprocess (30s limit, sensitive env vars stripped, temp CWD). The script prints a JSON verdict that's matched against an `expected_signature`. Includes crash-marker fallback detection. |
| **`generate_patch`** | Remediation | Produces patch code + description + risk level + CVE refs for a confirmed `vuln_node`; persisted as a `Mitigation` row. |

> **Sandbox note:** `execute_safe_poc` provides basic isolation (cleared secrets, temp workdir, timeout). A production deployment should add container isolation (gVisor / `docker --network=none` / a dedicated runtime).

---

## Vulnerability Correlation Engine

The agent produces three *independent* streams in `attack_graph.tool_results`: detections, PoCs, and patches. Historically these were rendered as three disjoint lists, so the UI could show "4 detected but 3 assessed" and PoCs collapsed onto a single vuln.

[`app/services/correlation.py`](app/services/correlation.py) fixes this by building **one canonical vulnerability per `(category, endpoint)`** and attaching exactly one definitive verification and one remediation to each:

- **Detections** come from DAST findings (`send_http_request` / `run_fuzzer` signals) plus network-service findings (e.g. a vsftpd 2.3.4 backdoor surfaced via `run_nmap` + a confirmed PoC).
- **PoCs** are matched to detections by endpoint-path tokens (strong signal) with category keywords as a weak tie-breaker; confirmed beats inconclusive.
- **Patches** are matched the same way, and — crucially — **every patch becomes its own vulnerability lane** even if no HTTP finding surfaced for it (so `remediated` is never under-counted).
- Each canonical vuln is then verified (explicit PoC, or "self-confirmed via live exploitation") so **`detected == tested`**.

The result is a coherent **detected / tested / remediated / total** count, and a final K2 pass (`FINAL_ASSESSMENT_PROMPT`) selects exactly **one definitive assessment entry per candidate** (CVSS, CVE, confidence) with the count pinned to the canonical total. A deterministic fallback keeps the UI consistent when K2 is offline.

The same correlation logic is mirrored in client-side JS so the live graph renders correct per-vulnerability lanes even for jobs whose stored data predates server-side correlation.

---

## Authentication & Account Model (Clerk)

Auth is handled by [Clerk](https://clerk.com) ([`app/services/auth.py`](app/services/auth.py)):

- The browser loads Clerk.js from `https://clerk.clerk.com/...` (the data-attribute v5 contract — the global `Clerk` is a ready instance).
- Every API `fetch` attaches `Authorization: Bearer <session JWT>` via a shared `window.getAuthHeaders()` helper.
- The backend verifies the JWT against Clerk's **JWKS** (RS256), caching the key map for 60 seconds.
- `require_user` (mandatory) and `get_current_user` (optional) FastAPI dependencies gate the routes.
- An **auth-wall middleware** redirects unauthenticated browser requests to `/sign-in`.

### Per-account ownership

The `Workspace.owner_id` column ties each registered domain to a Clerk `user_id`. **Only the owner can list, view, verify, scan, or download reports for their workspaces** (jobs inherit ownership from their workspace). Legacy rows with `owner_id = NULL` remain accessible (for migration/tests).

### Graceful degradation for local dev / tests

When `CLERK_SECRET_KEY` is **not set**, auth is disabled: `require_user` returns the constant `"test-user"`, and the entire test suite passes with zero mocking. Set the Clerk keys to turn auth on.

---

## Domain Verification

Before any scan can run, you must prove you own the target domain ([`app/services/verification.py`](app/services/verification.py)):

1. ThreatWeaver generates a per-workspace **nonce** (`SHA-256` of timestamp + `SECRET_KEY` + target).
2. You publish it as a DNS **TXT record** at `_threatweaver.<your-domain>`.
3. Click **Verify** — ThreatWeaver checks the record via **Cloudflare DNS-over-HTTPS** (`https://cloudflare-dns.com/dns-query` — fast, free, works over HTTPS so cloud VMs with blocked outbound UDP still resolve), falling back to the system resolver, then to an HTTP check at `https://<domain>/threatweaver.txt`.

If verification fails, the API returns a precise diagnostic (`verification_detail`) — e.g. *"expected X but DNS has Y"*, NXDOMAIN, no-TXT, or timeout — so you know exactly what to fix. For demos, `MOCK_VERIFICATION=true` bypasses the check.

---

## The Live Dashboard

The job page is a real-time, animated view that updates **in place via a 3-second poll loop — no page reloads** during a scan:

- **Attack graph** — a Vercel-style canvas node graph with lanes: `Recon → Scanning → Detection → PoC/Verification → Patch`. New nodes animate in (the connecting edge draws first, then the node "pops"). Pan/zoom is clamped to the content bounds; click a node card (outlined by type colour) to inspect it.
- **K2-Think-v2 token counter** — total / prompt / completion / API calls, animated count-up, tracking **all** K2 usage (agent reasoning, patch synthesis, final assessment).
- **Scan duration timer** — live `mm:ss` ticker that freezes to the exact start→end duration once the report is generated.
- **Severity & PDF report** — overall severity badge + download link.
- **K2 security assessment** — detected/tested/remediated/total counts + the per-vulnerability table (name, endpoint, severity, CVSS, confidence).
- **Mitigations** — per-vulnerability cards (description, CVE refs, recommended fix, patched-code accordion) that slide in as findings land.

A single clean reload happens only at the very end (to render the server-side report link + assessment table) and once on the first `pending/ready → recon` transition.

---

## Architecture & Tech Stack

| Layer | Technology |
|---|---|
| **Web framework** | FastAPI (fully async) |
| **Database** | SQLite via SQLAlchemy 2.0 async ORM (`aiosqlite`, WAL mode) |
| **Templating** | Jinja2 + Tailwind CSS (CDN) + Geist font |
| **Reasoning model** | K2-Think-v2 (via `LLMClient`) |
| **CVE research** | Brave Web Search API |
| **Auth** | Clerk (JWT / JWKS verification with PyJWT) |
| **DNS** | Cloudflare DNS-over-HTTPS + dnspython fallback |
| **PDF reports** | ReportLab |
| **Recon** | `nmap` subprocess |
| **Frontend graph** | Hand-rolled `<canvas>` renderer (no framework) |

---

## Project Structure

```
threat-weaver/
├── app/
│   ├── main.py                  # FastAPI app, auth-wall middleware, dashboard + sign-in routes
│   ├── database.py              # Async SQLAlchemy engine/session, init_db, SQLite WAL
│   ├── models.py                # ORM models: Workspace, AnalysisJob, Mitigation
│   ├── schemas.py               # Pydantic request/response models (+ SSRF target validation)
│   ├── templating.py            # Jinja2 environment
│   │
│   ├── routers/
│   │   ├── workspaces.py        # Workspace CRUD, verify, upload (ownership-enforced)
│   │   └── jobs.py              # Job create/start/get, mitigations, report, job HTML page
│   │
│   ├── services/
│   │   ├── orchestrator.py      # FSM + agentic loop, finalization, severity scoring
│   │   ├── k2_agent.py          # K2-Think-v2 ReAct agent (system prompt, decide loop)
│   │   ├── mcp_client.py        # Tool dispatcher: nmap, http, fuzzer, poc, cve, ...
│   │   ├── tool_executor.py     # Maps agent tool calls → MCPClient + side effects
│   │   ├── correlation.py       # Findings ↔ PoCs ↔ patches → canonical vulnerabilities
│   │   ├── remediation.py       # Patch generation + Mitigation persistence
│   │   ├── verification.py      # Cloudflare DoH / DNS / HTTP domain ownership check
│   │   ├── auth.py              # Clerk JWT/JWKS verification dependencies
│   │   ├── crypto.py            # Verification nonce generation
│   │   ├── report.py            # PDF report builder (ReportLab)
│   │   ├── llm_client.py        # K2-Think-v2 HTTP client + token usage capture
│   │   ├── llm_json.py          # Robust JSON extraction from LLM replies
│   │   └── ast_parser.py        # Source analysis / vuln-hash helpers
│   │
│   ├── templates/
│   │   ├── base.html            # Shell: nav, Clerk user menu, getAuthHeaders()
│   │   ├── index.html           # Dashboard: create workspace + list
│   │   ├── workspace.html       # Workspace detail: verify, start scan, jobs
│   │   ├── job_detail.html      # Live scan view: graph, tokens, timer, mitigations
│   │   └── sign_in.html         # Clerk sign-in / sign-up page
│   │
│   └── static/
│       └── style.css            # Vercel/shadcn design system + animations
│
├── demo-target/                 # "Nimbus CRM" — intentionally vulnerable scan target
│   ├── app.py                   # Flask app with planted vulnerabilities
│   ├── deploy.sh                # One-shot deploy (Nimbus CRM + vsftpd 2.3.4)
│   ├── requirements.txt
│   └── templates/               # login / dashboard / admin pages
│
├── tests/                       # pytest suite (132 tests)
├── requirements.txt
├── .env.example
└── README.md
```

---

## Data Model

### `workspaces`
| Column | Type | Notes |
|---|---|---|
| `id` | string (UUID) | PK |
| `target_url` | string | The domain to scan |
| `verification_nonce` | string | TXT-record value the owner must publish |
| `verification_status` | bool | Set true once DNS/HTTP check passes |
| `owner_id` | string, nullable, indexed | Clerk `user_id` of the owner |

### `analysis_jobs`
| Column | Type | Notes |
|---|---|---|
| `id` | string (UUID) | PK |
| `workspace_id` | string | FK → workspace |
| `status` | string | FSM internal state |
| `pipeline_phase` | string | High-water-mark phase for the UI |
| `overall_severity` | string | `low` … `extreme` |
| `attack_graph_data` | JSON | Everything: `tool_results`, `vulnerabilities`, `vulnerability_counts`, `token_usage`, `final_assessment`, `report`, `started_at`, `completed_at`, … |

### `mitigations`
| Column | Type | Notes |
|---|---|---|
| `id` | string (UUID) | PK |
| `job_id` | string | FK → job |
| `vulnerability_node` | string | The vuln this patch addresses |
| `remediation_code` | text | AI-generated patch |
| `finding_metadata` | JSON | `description`, `risk_level`, `cves`, `recommendation` |

---

## HTTP API Reference

> All `/api/*` routes require a valid Clerk session (unless `CLERK_SECRET_KEY` is unset). Ownership is enforced on every workspace/job resource.

### Workspaces
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/workspaces/` | Create a workspace (`{target_url}`) — stamps `owner_id`. |
| `GET` | `/api/workspaces/` | List the caller's workspaces. |
| `GET` | `/api/workspaces/{id}` | Get one workspace. |
| `POST` | `/api/workspaces/{id}/verify` | Run DNS/HTTP verification; returns `verification_status` + `verification_detail`. |
| `POST` | `/api/workspaces/{id}/upload` | Upload a source bundle (≤ 100 MB). |

### Jobs
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/jobs/` | Create a job for a **verified** workspace. |
| `POST` | `/api/jobs/{id}/start` | Launch the K2 pipeline (409 if already started/complete). |
| `GET` | `/api/jobs/{id}` | Poll job state (used by the live dashboard). |
| `GET` | `/api/jobs/{id}/mitigations` | List mitigations (full metadata). |
| `GET` | `/api/jobs/{id}/report` | Download the PDF report (regenerated on demand if missing). |

### Pages
| Path | Description |
|---|---|
| `/` | Dashboard |
| `/sign-in`, `/sign-up` | Clerk auth |
| `/workspaces/{id}` | Workspace detail |
| `/jobs/{id}` | Live scan view |

---

## Setup & Installation

### 1. Clone & configure
```bash
git clone https://github.com/a6dulr4hman/threat-weaver.git
cd threat-weaver
cp .env.example .env     # then fill in your keys (see below)
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
# (nmap must be installed on the host for recon: `apt install nmap` / `brew install nmap`)
```

### 3. Run
```bash
uvicorn app.main:app --reload
# → http://localhost:8000
```

### 4. Use
1. Sign in (Clerk).
2. Create a workspace for a domain you own.
3. Publish the TXT record at `_threatweaver.<domain>` and click **Verify**.
4. Click **Start scan** and watch the live attack graph.
5. Download the PDF report when it completes.

---

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `CLERK_PUBLISHABLE_KEY` | for auth | — | Clerk frontend key (safe to expose). |
| `CLERK_SECRET_KEY` | for auth | — | Clerk backend key. **Unset = auth disabled** (dev/tests). |
| `SECRET_KEY` | yes | — | Signs verification nonces. |
| `K2_API_KEY` | yes | — | K2-Think-v2 reasoning model API key. |
| `BRAVE_SEARCH_API_KEY` | for CVE lookup | — | Powers the `internet_search` CVE research tool. |
| `DATABASE_URL` | no | `sqlite+aiosqlite:///./threatweaver.db` | DB connection string. |
| `REPORT_DIR` | no | `/tmp/threatweaver/reports` | Where PDF reports are written. |
| `CYCLE_BUDGET_SECONDS` | no | `480` | Wall-clock budget per scan cycle (see limits). |
| `MOCK_VERIFICATION` | no | `false` | Bypass domain verification (demo only — leaves DAST unlocked). |

---

## The Demo Target — Nimbus CRM

`demo-target/` contains **Nimbus CRM**, a small Flask app that *looks* like an ordinary internal CRM (login, customer search, document export, admin diagnostics, report builder) but ships realistic, planted vulnerabilities woven into ordinary features:

| Endpoint | Vulnerability class |
|---|---|
| `POST /login` | SQL injection → auth bypass |
| `GET /customers?q=` | SQL injection (error-leaking) |
| `GET /customer/<id>` | SQL injection |
| `GET /download?file=` | Path traversal |
| `GET /admin/diagnostics?host=` | OS command injection (`subprocess shell=True`) |
| `GET /admin/backup?label=` | OS command injection (`os.system`) |
| `GET /reports/compute?formula=` | Code execution (`eval`) |
| FTP `:21` | vsftpd 2.3.4 backdoor (CVE-2011-2523) |

> The demo source has **no "VULNERABILITY HERE" hints** — the flaws are discoverable by genuine code/behaviour analysis, so the agent must earn its findings. `deploy.sh` stands it up on port 80 (+ vsftpd on 21) on a disposable VM. **Tear it down after the demo.**

---

## Configuration & Safety Limits

The scan is bounded by several guardrails so a runaway loop can't exhaust tokens or hang the server:

| Limit | Value | Where | Effect |
|---|---|---|---|
| `MAX_ITERATIONS` | **30** | `k2_agent.py` | Max agent steps (tool calls) per scan cycle. |
| `CYCLE_BUDGET_SECONDS` | **480** (env) | `orchestrator.py` | Wall-clock cap per cycle. Often the real terminator. |
| `MAX_ATTACK_ATTEMPTS` | **3** | `orchestrator.py` | Non-anomalous payloads per endpoint before forced pivot (an anomaly resets it). |
| `MAX_PATCHES` | **7** | `orchestrator.py` | Max remediations per job (matches Nimbus CRM's vuln count). |
| `MAX_HISTORY_MESSAGES` | **30** | `k2_agent.py` | Rolling conversation window (token budget). |
| `MAX_PARSE_RETRIES` | **2** | `k2_agent.py` | JSON-format correction nudges before erroring. |

**Tuning tip:** if scans terminate before exploring everything, the cause is almost always `CYCLE_BUDGET_SECONDS` (K2 reasoning calls are slow). Raise it in `.env`, e.g. `CYCLE_BUDGET_SECONDS=900`.

---

## Testing

```bash
python3 -m pytest tests/ -v
```

The suite (132 tests) covers the orchestrator FSM, correlation engine, MCP tools, remediation, report generation, templates, workspaces, and jobs. Auth is transparently disabled in tests (no Clerk keys), so `require_user` yields `"test-user"` and no mocking is required.

---

## Security Considerations

- **Target validation** — `WorkspaceCreate` rejects IP addresses, `localhost`, and private/reserved/link-local/metadata ranges (SSRF guard).
- **Ownership enforcement** — every workspace/job/report resource is gated by the Clerk `owner_id`; cross-account access returns `403`.
- **PoC sandboxing** — `execute_safe_poc` strips secrets from the subprocess env, uses a temp CWD, and enforces a 30s timeout (harden further with container isolation in production).
- **Secrets** — never commit `.env`; the Clerk secret key and `K2_API_KEY` are server-side only.
- **Authorized scanning only** — domain verification ensures you can only attack domains you control.

---

## Reports

After a scan completes, a PDF vulnerability report ([`app/services/report.py`](app/services/report.py)) is generated containing severity, recon services, per-finding details, the K2 assessment table, and full remediation code. Download it from the job page ("Download PDF report") or `GET /api/jobs/{job_id}/report`. Reports are written to `REPORT_DIR` and regenerated on demand if the file is missing.

---

## Glossary

| Term | Meaning |
|---|---|
| **DAST** | Dynamic Application Security Testing — black-box testing of the running app. |
| **ReAct** | Reason + Act — the LLM alternates internal reasoning with tool actions. |
| **PoC** | Proof of Concept — a script that reproduces/confirms an exploit. |
| **FSM** | Finite State Machine — the phase model driving the pipeline. |
| **Nonce** | One-time verification token published in DNS to prove domain ownership. |
| **JWKS** | JSON Web Key Set — Clerk's public keys used to verify session JWTs. |
| **DoH** | DNS-over-HTTPS — DNS resolution over an HTTPS API (Cloudflare). |

---

<div align="center">

**ThreatWeaver** — built to find what your scanners miss, prove it's real, and write the fix.

</div>
