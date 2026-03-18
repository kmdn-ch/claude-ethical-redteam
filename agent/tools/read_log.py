import os
import json

LOGS_DIR = "logs"


def run(filename: str = "") -> str:
    """Read a result file from logs/ or list all available log files."""
    logs_abs = os.path.abspath(LOGS_DIR)

    if not filename:
        entries = []
        for root, _, files in os.walk(logs_abs):
            for f in sorted(files):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, logs_abs)
                size = os.path.getsize(path)
                entries.append(f"  {rel} ({size} bytes)")
        if not entries:
            return "📂 logs/ is empty"
        return "📂 Available logs:\n" + "\n".join(entries)

    # Security: block path traversal
    target = os.path.abspath(os.path.join(LOGS_DIR, filename))
    if not target.startswith(logs_abs + os.sep) and target != logs_abs:
        return "❌ Access denied: path outside logs/"

    if not os.path.exists(target):
        return f"❌ File not found: {filename}"

    try:
        with open(target, encoding="utf-8", errors="replace") as f:
            content = f.read()

        if not content.strip():
            return f"📄 {filename}: (empty)"

        if filename.endswith(".json"):
            lines = [l.strip() for l in content.splitlines() if l.strip()]

            # Try JSONL (nuclei format — multiple JSON objects, one per line)
            parsed = []
            for line in lines:
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            if len(parsed) > 1:
                summary = f"📄 {filename} – {len(parsed)} entries:\n"
                for entry in parsed[:20]:
                    if "info" in entry:  # nuclei finding
                        cve_list = (entry.get("info", {}).get("classification") or {}).get("cve-id") or []
                        cve = cve_list[0] if cve_list else entry.get("template-id", "")
                        name = entry.get("info", {}).get("name", "?")
                        sev = entry.get("info", {}).get("severity", "?").upper()
                        host = entry.get("matched-at", entry.get("host", "?"))
                        summary += f"  [{sev}] {cve or name} → {host}\n"
                    else:
                        summary += f"  {json.dumps(entry)[:120]}\n"
                if len(parsed) > 20:
                    summary += f"  ... +{len(parsed) - 20} more"
                return summary.strip()

            if len(parsed) == 1:
                # Single JSON object (e.g. ffuf output)
                data = parsed[0]
                results = data.get("results", [])
                if results:
                    summary = f"📄 {filename} – {len(results)} results:\n"
                    for r in results[:20]:
                        status = r.get("status", "?")
                        url = r.get("url", (r.get("input") or {}).get("FUZZ", "?"))
                        length = r.get("length", "?")
                        summary += f"  [{status}] {url} ({length}b)\n"
                    if len(results) > 20:
                        summary += f"  ... +{len(results) - 20} more"
                    return summary.strip()
                return f"📄 {filename}:\n{json.dumps(data, indent=2)[:3000]}"

        # Plain text (sqlmap, bettercap, etc.)
        if len(content) > 3000:
            return f"📄 {filename} (first 3000 chars):\n{content[:3000]}\n..."
        return f"📄 {filename}:\n{content}"

    except Exception as e:
        return f"❌ Error reading {filename}: {str(e)}"


TOOL_SPEC = {
    "name": "read_log",
    "description": (
        "Read a result file from logs/ (nuclei, ffuf, sqlmap, recon, etc.) "
        "or list all available log files. Call with no argument to list files."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": (
                    "Filename to read (e.g. 'nuclei.json', 'ffuf.json', 'sqlmap/target/log'). "
                    "Leave empty to list all available log files."
                ),
            }
        },
        "required": [],
    },
}
