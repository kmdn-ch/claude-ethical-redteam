# Phantom — Project Vision & Session Context

## What is Phantom
A fully autonomous AI red team agent. Open-source, free forever.

## Why it exists
To prove that AI can do offensive security autonomously — reason, adapt, chain exploits, write its own tools, and infiltrate targets without human guidance.

## For whom
Anyone curious enough to try it, any skill level. No security background required.

## Core Principles
1. **Full autonomy** — the agent decides its own attack strategy from scratch. No predefined kill chain. It reasons freely, adapts based on findings, and invents novel attack chains by combining discoveries.
2. **Dynamic tool generation** — when Phantom encounters something its built-in tools can't handle, it writes and executes custom scripts on the fly. This is the essence of the project.
3. **0-day discovery** — fuzzing and discovering actual unknown vulnerabilities in targets, not just running known CVE checks.
4. **Full exploitation** — establish persistence, pivot laterally, exfiltrate data. Fully unsupervised within scope boundaries.
5. **Hard scope walls** — total freedom inside authorized scope, absolute zero outside it.
6. **Debrief** — after a mission, Phantom returns to the human with a precise timeline + visual attack graph of everything it did, with extreme precision.

## Current State (v2.7.8)
- ~50% of the vision. It works, scans, and follows a path — but it feels linear and scripted.
- The architecture needs to support true autonomy, self-reasoning, and dynamic tool generation.

## Architecture Constraints
- **Local LLM support (Ollama) is sacred** — must always work offline with local models.
- **Language:** Python core, but open to any language (Rust, Go, etc.) if the architecture calls for it.
- **Testing:** Rigorous test coverage required.
- **Web UI:** Not a priority. CLI-first.

## Conventions
- Commits in English, conventional format (feat/fix/ci/docs/etc.)
- Python: `python -m ruff format` before any commit (line-length=100)
- Always update README.md when creating a new release/push

## Repo
- GitHub: https://github.com/kmdn-ch/phantom-ethical-redteam (public)
- Owner: KMDN (Switzerland)
- Working directory: `C:\Users\User\phantom-ethical-redteam`
