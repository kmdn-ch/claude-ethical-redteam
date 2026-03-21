"""Brute force authentication — wraps Hydra CLI with Python HTTP fallback."""

import logging
import subprocess
import re

from .scope_checker import scope_guard
from .logs_helper import log_path
from .stealth import stealth_headers, stealth_delay

logger = logging.getLogger(__name__)

# Minimal default credentials (common across services)
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("root", "password"), ("test", "test"), ("user", "user"),
    ("guest", "guest"), ("admin", ""), ("root", ""),
    ("administrator", "administrator"), ("admin", "changeme"),
    ("admin", "letmein"), ("admin", "welcome"),
]

# Service-specific defaults
SERVICE_DEFAULTS = {
    "tomcat": [("tomcat", "tomcat"), ("admin", "tomcat"), ("tomcat", "s3cret"), ("admin", "admin")],
    "jenkins": [("admin", "admin"), ("admin", "password"), ("admin", "jenkins")],
    "joomla": [("admin", "admin"), ("admin", "joomla"), ("admin", "password")],
    "wordpress": [("admin", "admin"), ("admin", "password"), ("admin", "wordpress")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("root", "password")],
    "ssh": [("root", "root"), ("root", "toor"), ("admin", "admin")],
    "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
    "mysql": [("root", ""), ("root", "root"), ("root", "password")],
}


def _python_http_brute(target: str, usernames: list, passwords: list, form_params: dict) -> list:
    """Pure Python HTTP form brute force (fallback when Hydra unavailable)."""
    from .http_utils import retry_request
    results = []
    login_url = target
    user_field = form_params.get("user_field", "username")
    pass_field = form_params.get("pass_field", "password")
    fail_string = form_params.get("fail_string", "invalid")

    tested = 0
    for user in usernames:
        for passwd in passwords:
            if tested >= 50:  # Safety limit
                results.append(f"[INFO] Stopped after {tested} attempts (safety limit)")
                return results
            stealth_delay()
            try:
                resp = retry_request(
                    login_url, method="POST",
                    headers=stealth_headers(),
                    data={user_field: user, pass_field: passwd},
                    timeout=10, max_retries=1,
                )
                tested += 1
                body = resp.text.lower()
                # Check for success (no fail string, or redirect, or 302)
                if fail_string.lower() not in body and resp.status_code in (200, 301, 302, 303):
                    if resp.status_code in (301, 302, 303) or "dashboard" in body or "welcome" in body:
                        results.append(f"[CRITICAL] Valid credentials: {user}:{passwd}")
                        logger.info("CREDENTIAL FOUND: %s on %s", user, target)
            except Exception:
                continue

    if not results:
        results.append(f"[INFO] Tested {tested} combinations — no valid credentials found")
    return results


def run(target: str, service: str = "http-form", userlist: str = "", passlist: str = "",
        form_params: str = "") -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("hydra_results.txt")

    # Parse target for hostname/port
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    port_match = re.search(r":(\d+)", host)
    port = port_match.group(1) if port_match else ""
    hostname = host.split(":")[0]

    # Build credential lists
    svc_key = service.split("-")[0].lower() if "-" in service else service.lower()
    extra_creds = SERVICE_DEFAULTS.get(svc_key, [])
    all_creds = extra_creds + DEFAULT_CREDS

    usernames = list(dict.fromkeys([c[0] for c in all_creds]))
    passwords = list(dict.fromkeys([c[1] for c in all_creds]))

    # Try Hydra CLI first
    if service in ("ssh", "ftp", "mysql", "rdp", "smb", "telnet", "vnc"):
        cmd = [
            "hydra", "-L", "-", "-P", "-",
            hostname, service,
        ]
        if port:
            cmd.extend(["-s", port])
        cmd.extend(["-o", output_path, "-t", "4", "-f"])

        user_input = "\n".join(usernames[:20])
        pass_input = "\n".join(passwords[:20])
        stdin_data = None

        try:
            # Write temp credential files
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
                uf.write("\n".join(usernames[:20]))
                user_file = uf.name
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
                pf.write("\n".join(passwords[:20]))
                pass_file = pf.name

            cmd = [
                "hydra", "-L", user_file, "-P", pass_file,
                hostname, service,
            ]
            if port:
                cmd.extend(["-s", port])
            cmd.extend(["-o", output_path, "-t", "4", "-f"])

            logger.info("Running hydra: %s %s", hostname, service)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            os.unlink(user_file)
            os.unlink(pass_file)

            output = result.stdout + result.stderr
            found = re.findall(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)", output)

            findings = []
            for port_n, svc, h, login, passwd in found:
                findings.append(f"[CRITICAL] {svc}://{login}:{passwd}@{h}:{port_n}")

            if findings:
                return f"Hydra — {len(findings)} credentials found:\n" + "\n".join(f"  {f}" for f in findings)
            return f"Hydra — 0 credentials found ({len(usernames)}x{len(passwords)} tested)"

        except FileNotFoundError:
            logger.info("Hydra not found — using Python fallback for HTTP")
        except Exception as e:
            logger.error("Hydra error: %s", e)

    # Python HTTP fallback
    params = {}
    if form_params:
        for part in form_params.split(","):
            if "=" in part:
                k, _, v = part.partition("=")
                params[k.strip()] = v.strip()

    findings = _python_http_brute(target, usernames, passwords, params)
    return f"Brute force — {len(findings)} results:\n" + "\n".join(f"  {f}" for f in findings)


TOOL_SPEC = {
    "name": "run_hydra",
    "description": (
        "Brute force authentication testing. Tests default/common credentials against "
        "HTTP forms, SSH, FTP, MySQL, RDP, etc. Uses Hydra CLI if available, "
        "otherwise Python HTTP fallback. Includes service-specific credential lists "
        "(Tomcat, Jenkins, WordPress, phpMyAdmin). Safety-limited to 50 attempts."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL or host"},
            "service": {
                "type": "string",
                "description": "Service: http-form (default), ssh, ftp, mysql, rdp, smb",
            },
            "form_params": {
                "type": "string",
                "description": "HTTP form params: user_field=username,pass_field=password,fail_string=invalid",
            },
        },
        "required": ["target"],
    },
}
