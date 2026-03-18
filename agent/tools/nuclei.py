import os
import subprocess
import json


def run(target: str, templates: str = "http/cves", severity: str = "critical") -> str:
    output_path = os.path.join("logs", "nuclei.json")
    cmd = [
        "nuclei", "-u", target, "-t", templates,
        "-severity", severity, "-json", "-silent", "-o", output_path,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        # Nuclei outputs JSONL — parse from stdout first, fallback to output file
        source = result.stdout.strip()
        if not source and os.path.exists(output_path):
            with open(output_path, encoding="utf-8", errors="replace") as f:
                source = f.read()

        findings = []
        for line in source.splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        if not findings:
            return "✅ Nuclei done – 0 findings"

        summary = f"✅ Nuclei done – {len(findings)} findings:\n"
        for finding in findings[:15]:
            cve_list = (finding.get("info", {}).get("classification") or {}).get("cve-id") or []
            cve = cve_list[0] if cve_list else finding.get("template-id", "")
            name = finding.get("info", {}).get("name", "unknown")
            sev = finding.get("info", {}).get("severity", "?").upper()
            matched = finding.get("matched-at", finding.get("host", ""))
            summary += f"  [{sev}] {cve or name} → {matched}\n"

        if len(findings) > 15:
            summary += f"  ... +{len(findings) - 15} more (use read_log 'nuclei.json' for full details)"

        return summary.strip()
    except Exception as e:
        return f"❌ Error Nuclei : {str(e)}"


TOOL_SPEC = {
    "name": "run_nuclei",
    "description": "Launch a fast Nuclei scan and targeted (CVEs, misconfigs, etc.)",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "templates": {"type": "string", "default": "http/cves"},
            "severity": {"type": "string", "default": "critical"},
        },
        "required": ["target"],
    },
}
