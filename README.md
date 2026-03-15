# Phantom – Claude Ethical Red Team

**Autonomous Red Team agent powered by Claude AI**
Uses Nuclei, sqlmap, ffuf, advanced reconnaissance, and social engineering templates — on authorized scopes only.

> **Legal notice:** This project is intended solely for lawful security research and authorized testing in controlled environments. Use only on assets you own or are expressly authorized in writing to assess. Nothing in this repository grants authorization to target third-party systems.

![Phantom in action](images/phantom-banner.png)

---

## Features

- Autonomous agent with step-by-step reasoning + auto-correction
- Native Claude tool-calling (Nuclei, sqlmap, ffuf, recon, bettercap, cleanup, phishing templates)
- Full logging + automatic cleanup of temporary files
- Pause every N turns — human can stop, continue, or force a report
- Social engineering limited to educational templates (no actual send without human confirmation)

## Built-in Tools

| Tool | Role |
|---|---|
| Nuclei | CVE / misconfiguration scanning |
| sqlmap | SQL injection detection & exploitation |
| ffuf | Directory & endpoint fuzzing |
| recon | Passive reconnaissance (DNS, WHOIS, headers) |
| bettercap | Network MITM, ARP probe (lab only) |
| Zphisher | Phishing page templates (educational) |
| CyberStrikeAI | AI-native orchestrator — 100+ tools |

---

## Installation

```bash
./install.sh
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Real-world example — Web application pentest

### Context

You are a red teamer hired to test the security of `https://someth1ng.com`.
The client has signed a Rules of Engagement document. The scope is limited to this domain and its subdomains.

### Step 1 — Define the scope

Edit `scopes/current_scope.md`:

```markdown
**Scope autorisé :** https://someth1ng.com

**Subdomains in scope:** *.someth1ng.com

**Autorisation :** Pentest contract signed 2026-03-15 — full web application test
```

### Step 2 — Launch Phantom

```bash
python agent/main.py
```

```
🚀 Phantom - Claude Ethical RedTeam v1.0
Mode : AUTONOME TOTAL
Scope : https://someth1ng.com — Pentest contract signed 2026-03-15...
```

### Step 3 — Phantom reasons and acts autonomously

Phantom works through the standard kill chain, narrating every decision:

```
🤖 Phantom : Starting mission on https://someth1ng.com.
  Result obtained: scope confirmed.
  Analysis: I will begin with passive recon before any active scan.
  Next optimal action: run_recon on the target.
  Reason: passive data collection has zero impact on availability.

🔧 Execution : run_recon
→ DNS records, WHOIS, HTTP headers, tech stack fingerprinting...

🤖 Phantom : Result obtained: Apache 2.4.51, PHP 8.0, WordPress 6.1.
  Analysis: WordPress 6.1 is EOL — multiple known CVEs. Apache version exposed.
  Next optimal action: run_nuclei with wordpress templates.
  Reason: high probability of CVE hits before any brute-force or injection.

🔧 Execution : run_nuclei
→ Target: https://someth1ng.com, templates: http/cves, severity: critical

🤖 Phantom : Result obtained: 3 findings — CVE-2023-2745 (path traversal),
  CVE-2022-3590 (SSRF via pingback), misconfigured xmlrpc.php.
  Analysis: CVE-2023-2745 exploitable without auth — direct path to /etc/passwd.
  Next optimal action: run_sqlmap on login endpoint discovered by ffuf.
  Reason: parallel track — test both path traversal and SQL injection.

🔧 Execution : run_ffuf
→ Discovered: /admin, /wp-login.php, /api/v1/users, /backup.zip

🔧 Execution : run_sqlmap
→ Target: https://someth1ng.com/api/v1/users?id=1
→ Injection found: UNION-based, 4 columns — database: someth1ng_prod
```

After 10 turns, Phantom pauses:

```
⏸️  Pause after 10 steps (mode autonome).
Entrée = continue | 'stop' = stop | 'report' = force report :
```

You review the logs in `logs/agent.log`, then press Enter to continue — or type `report` to get an immediate executive summary.

### Step 4 — Mission complete

```
🤖 Phantom : Objectives achieved. Generating final report.

=== MISSION COMPLETE ===

**Executive Summary**
app.someth1ng.com presents 3 critical vulnerabilities exploitable without authentication.

**Critical findings**
1. CVE-2023-2745 — WordPress path traversal → arbitrary file read (PoC: /wp-admin/?action=..&page=../../../etc/passwd)
2. SQL injection on /api/v1/users?id= → full database dump (someth1ng_prod, 12 tables, 4 200 users)
3. /backup.zip publicly accessible → contains database credentials in plaintext

**Recommendations**
- Patch WordPress to 6.5+ immediately
- Parameterize all SQL queries — use prepared statements
- Remove /backup.zip and audit all publicly accessible backup files
- Disable xmlrpc.php if not required
```

All findings are in `logs/` — ready to import into your report.

---

## Configuration

`config.yaml`:

```yaml
model: "claude-3-5-sonnet-20241022"
autonomous: true
max_autonomous_turns: 50    # hard cap — agent stops after N turns
pause_every_n_turns: 10     # human checkpoint frequency
```

API key must be set as environment variable — never stored in config:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Legal

This tool is for authorized penetration testing only. Running it against systems you do not have written permission to test is illegal. The authors are not responsible for misuse.
