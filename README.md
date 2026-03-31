# Phantom - Ethical RedTeam

> An autonomous AI red team agent that thinks, adapts, and hacks like a real attacker.

![Phantom in action](images/phantom-banner.png)

Phantom is an open-source autonomous offensive security agent. Point it at an authorized target, and it reasons through the entire attack chain on its own — no predefined phases, no hand-holding, no fixed script. It forms its own attack hypotheses, pursues multiple vectors simultaneously, writes custom tools when it needs them, and delivers a full debrief when it's done.

**This project exists to prove one thing:** AI can do offensive security autonomously.

> **Legal notice:** Use only on systems you own or have written authorization to test. Nothing in this repository grants permission to target third-party systems.

---

## Why Phantom?

Most security tools run a checklist. Phantom doesn't. It:

- **Reasons like an attacker** — forms concurrent hypotheses, pursues the highest-impact ones first, abandons dead ends and spawns new vectors
- **Chains findings** — combines vulnerabilities into real exploitation paths (SSRF + internal metadata = cloud credentials = RCE)
- **Writes its own tools** — when built-in tools aren't enough, it generates and executes custom Python scripts on the fly
- **Never stops on its own** — missions run until all attack vectors are exhausted, not until a timer goes off
- **Debriefs with precision** — timeline, attack graph, full chain reconstruction, nothing left out

---

## Quick Start

### One-liner install

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/kmdn-ch/phantom-ethical-redteam/main/get.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/kmdn-ch/phantom-ethical-redteam/main/get.ps1 | iex
```

### Manual install

```bash
git clone https://github.com/kmdn-ch/phantom-ethical-redteam.git ~/phantom
cd ~/phantom
chmod +x install.sh
./install.sh
```

### Run a mission (v3 autonomous engine)

```bash
source .venv/bin/activate
export $(cat .env)
python3 agent/main.py --v3
```

### Resume a mission

```bash
python3 agent/main.py --v3 --resume 20260318_120000
```

---

## Supported LLM Providers

Phantom works with any of these out of the box. Local models via Ollama are fully supported — no cloud required.

| Provider | Default Model | API Key Env Var |
|---|---|---|
| Anthropic (Claude) | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| OpenAI (ChatGPT) | `gpt-5.4` | `OPENAI_API_KEY` |
| xAI (Grok) | `grok-4-20-beta` | `XAI_API_KEY` |
| Google (Gemini) | `gemini-3.0-pro` | `GEMINI_API_KEY` |
| Mistral | `mistral-large-latest` | `MISTRAL_API_KEY` |
| DeepSeek | `deepseek-chat-v3.2` | `DEEPSEEK_API_KEY` |
| Ollama (local) | `deepseek-v3.2:cloud` | *(none)* |

---

## What's in the Toolbox

### Reconnaissance
- **Subdomain discovery** — passive enumeration via crt.sh + HackerTarget
- **Port scanning** — Nmap with quick, service, full, and vuln scan modes
- **Tech fingerprinting** — WhatWeb with Python fallback
- **Auto recon** — single call that runs nmap + whatweb + sensitive file probing and generates attack hypotheses from results

### Scanning & Fuzzing
- **CVE scanning** — Nuclei for known vulnerabilities and misconfigurations
- **WordPress scanner** — version, users, plugins, xmlrpc, debug.log, config backups
- **Directory fuzzing** — ffuf for hidden endpoints
- **SQL injection** — sqlmap detection and exploitation
- **Payload library** — PayloadsAllTheThings integration (13 attack categories)
- **Dynamic tool forge** — LLM writes and executes targeted Python scripts for anything not covered

### Exploitation & Network
- **Auto exploit** — takes a confirmed finding and immediately generates + runs a targeted exploit script
- **Credential brute force** — Hydra for HTTP, SSH, FTP, MySQL, RDP
- **Metasploit** — module search, exploit execution, auxiliary scanning
- **JWT attacks** — HS256 brute force, alg=none, claim tampering, token forging
- **GraphQL enumeration** — introspection, schema dump, sensitive field discovery
- **Privilege escalation** — Linux/Windows enumeration (SUID, sudo, Docker, SeImpersonate)
- **Network MITM** — ARP probing via Bettercap (Linux only)

### Evidence & Stealth
- **Screenshots** — Playwright / wkhtmltoimage / Chromium capture
- **Auth management** — bearer, basic, cookie, custom headers per target
- **Stealth profiles** — 4 modes (silent / stealthy / normal / aggressive) with UA rotation and proxy support

### Reporting
- **Report generation** — Markdown + HTML + optional PDF
- **Mission diff** — compare sessions to track remediation (new / resolved / persistent)
- **Risk scoring** — aggregate CVSS from findings
- **Scope check** — hard boundary enforced before every network action
- **Log reader** — parse Nuclei JSONL, ffuf JSON, and other tool outputs

---

## How It Works

Phantom v3 runs a **Plan-Act-Observe-Reflect** loop driven by a **hypothesis priority queue** — not a turn counter.

```
Mission start
  │
  ├─ Seed: 6 concurrent initial hypotheses per target
  │    "SQLi/SSTI/SSRF on all input surfaces"
  │    "Exposed .env/.git/swagger/admin endpoints"
  │    "Default credentials on auth surfaces"
  │    "Open ports → targeted service attacks"
  │    ...
  │
  └─ Loop (runs until all hypotheses exhausted):
       PLAN  — LLM picks highest-priority hypotheses, creates multi-vector plan
       ACT   — Runs up to 4 tools in parallel
       OBSERVE — Extracts findings, feeds new hypotheses back into queue
       REFLECT — If stalled: pivot. If critical found: escalate immediately.
       STRATEGIST (every 5 turns) — Injects high-level attack chain analysis
```

Every confirmed finding automatically generates follow-up hypotheses:
- Injection finding → blind SQLi + time-based + SSTI
- Exposed config file → credential read + backup file search
- Auth weakness → privilege escalation + password reuse
- Open DB port → default credentials + external access test
- Admin panel → default creds + auth bypass + privesc

The mission ends when the queue is exhausted — not when a timer runs out.

---

## What a mission looks like

```
=== Turn 1/100 ===
Phantom: Forming initial hypotheses. Pursuing 3 vectors simultaneously.

<plan_create objective="Web injection + config exposure + auth" priority="0.95">
  <action tool="run_auto_recon" args='{"target": "https://target.com"}' priority="0.9"/>
  <action tool="run_nuclei" args='{"target": "https://target.com"}' priority="0.85"/>
  <action tool="forge_tool" args='{"description": "SSTI probe all reflected params"}' priority="0.8"/>
</plan_create>

  >> Running: run_auto_recon, run_nuclei, forge_tool

[INFO] Port 22 open: OpenSSH 8.9
[INFO] Port 443 open: HTTPS / Apache 2.4.51
[HIGH] CVE-2023-2745: wp-admin path traversal
[CRITICAL] SSTI confirmed: /search?q={{7*7}} returns 49

=== Turn 2/100 ===
Phantom: Critical SSTI confirmed. Spawning exploit chain immediately.

  >> Running: forge_tool (RCE via SSTI), screenshot

[CRITICAL] RCE: /search?q={{"".__class__.__mro__[1]...}} returns uid=33(www-data)
[CRITICAL] Persistence: cron job written to /etc/cron.d/phantom

=== MISSION COMPLETE ===
Findings: 14 | Chains: 3 | Critical: 2 | High: 5
```

---

## Configuration

```yaml
# config.yaml
provider: "anthropic"        # anthropic | openai | grok | gemini | ollama | mistral | deepseek
model: ""                    # leave empty for provider default
autonomous: true
max_autonomous_turns: 100    # hard cap; mission usually ends earlier via hypothesis exhaustion
pause_every_n_turns: 10      # operator checkpoint interval (v2 only; v3 runs fully autonomous)

# Performance
max_parallel_tools: 4        # concurrent tool execution per turn
requests_per_second: 5       # rate limit for tool calls
retry_max: 3                 # retries with exponential backoff

# Stealth
stealth_profile: "normal"    # silent | stealthy | normal | aggressive
# proxy: "http://127.0.0.1:8080"  # route through Burp
```

### Scope file (`scopes/current_scope.md`)

```markdown
# Authorized targets
https://target.com
https://api.target.com
192.168.1.0/24

# Authorization: Pentest contract signed 2026-03-15
```

---

## Project Structure

```
phantom/
  agent/
    main.py                        # Entry point (--v3 flag for autonomous engine)
    orchestrator.py                # PAOR loop + hypothesis engine integration
    agent_client.py                # v2 legacy loop
    providers/                     # 7 LLM provider adapters
    reasoning/
      hypothesis_engine.py         # Priority queue driven by findings
      planner.py                   # XML plan block parser
      reflector.py                 # Stall detection + pivot decisions
      strategist.py                # Attack chain analysis
      context_manager.py           # Token-budget-aware prompt builder
    tools/                         # Tool implementations
    models/                        # Data models (findings, graph, events, state)
  prompts/
    system_prompt_v3.txt           # Attacker-mindset system prompt
    initial_mission.txt            # Aggressive mission seed template
    forge_tool_prompt.txt          # Script generation format instructions
  tests/                           # 246 unit tests
  scopes/                          # Scope templates
  install.sh / install.ps1         # Interactive installers
  get.sh / get.ps1                 # One-liner downloaders
```

---

## Mission Diff (Remediation Tracking)

Compare two sessions to see what got fixed and what's still open:

```
Mission Diff: session_A -> session_B

  NEW (1):
    [+] [HIGH] CVE-2024-1234

  RESOLVED (8):
    [-] [CRITICAL] CVE-2023-2745
    [-] [HIGH] SQLi on /api/users

  PERSISTENT: 7 findings
```

---

## Changelog

### v3.1.0
- **Hypothesis-driven engine** — missions are driven by a priority queue of attack hypotheses, not a turn counter. The mission ends when all attack vectors are exhausted.
- **Auto follow-up generation** — every confirmed finding automatically spawns targeted follow-up hypotheses (injection → blind SQLi + SSTI; auth weakness → privesc; exposed port → targeted service attack)
- **Fixed reflection pipeline** — the reflect phase was a stub that did nothing; now parses `<reflection>` blocks and drives actual pivot decisions
- **Strategist feedback loop** — strategic analysis results are now injected back into the LLM conversation as guidance messages
- **Real tool output parsing** — finding extraction now handles actual nmap/nuclei/whatweb/ffuf output formats (not just `[CRITICAL]` tags that tools never emit)
- **Aggressive system prompt** — rewritten from 53 lines of passive instructions to 137 lines of attacker-mindset reasoning, covering SSTI, SSRF, prototype pollution, JWT forgery, deserialization, 0-day fuzzing, and chain-thinking examples
- **Multi-vector mission seeding** — initial message now seeds 6 concurrent hypotheses per target across all attack surface categories
- **Max turns raised** — default 80 → 100 (mission usually ends earlier via hypothesis exhaustion)

### v3.0.x
- v3 PAOR orchestrator replacing v2 linear loop
- Dynamic Tool Forge (LLM generates and executes custom Python scripts)
- MissionMemory with SQLite persistence
- AttackGraph with Mermaid visualization
- ReflectionLayer with stall detection and pivot decisions
- XML plan block parsing for structured LLM output
- 246 unit tests

---

## Legal

This tool is for **authorized penetration testing only**. Running it against systems you do not have written permission to test is illegal. The authors are not responsible for misuse.

---

*Built by [KMDN](https://github.com/kmdn-ch) — Switzerland*
