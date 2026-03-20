"""Phantom Web Dashboard — Flask + SocketIO with structured data."""

import os
import re
import sys
import json
import time
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO
from flask_cors import CORS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Track running mission
_mission_thread = None
_mission_stop = threading.Event()


# ---------------------------------------------------------------------------
# Structured result parsers
# ---------------------------------------------------------------------------

def parse_nuclei_output(raw: str) -> list:
    """Parse nuclei text output into structured findings."""
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Nuclei format: [severity] [template-id] [protocol] url [extra]
        m = re.match(
            r"\[(?P<sev>critical|high|medium|low|info)\]\s+"
            r"\[(?P<tid>[^\]]+)\]\s+"
            r"\[(?P<proto>[^\]]+)\]\s+"
            r"(?P<url>\S+)\s*(?P<extra>.*)",
            line, re.IGNORECASE,
        )
        if m:
            findings.append({
                "severity": m.group("sev").lower(),
                "template": m.group("tid"),
                "protocol": m.group("proto"),
                "url": m.group("url"),
                "extra": m.group("extra").strip(),
            })
        # Also match bracket-only severity mentions
        elif re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.IGNORECASE):
            sev_m = re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.IGNORECASE)
            findings.append({
                "severity": sev_m.group(1).lower(),
                "template": "",
                "protocol": "",
                "url": "",
                "extra": line,
            })
    return findings


def parse_nmap_output(raw: str) -> dict:
    """Parse nmap text output into structured data."""
    ports = []
    host_info = {}
    for line in raw.splitlines():
        # Open port lines: 80/tcp open http Apache httpd 2.4.x
        pm = re.match(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", line)
        if pm:
            ports.append({
                "port": int(pm.group(1)),
                "protocol": pm.group(2),
                "state": pm.group(3),
                "service": pm.group(4),
                "version": pm.group(5).strip(),
            })
        if "Nmap scan report for" in line:
            host_info["target"] = line.split("for")[-1].strip()
        if "Host is up" in line:
            host_info["status"] = "up"
            latency = re.search(r"\(([\d.]+)s latency\)", line)
            if latency:
                host_info["latency"] = latency.group(1)
    return {"host": host_info, "ports": ports}


def parse_ffuf_output(raw: str) -> list:
    """Parse ffuf results."""
    results = []
    for line in raw.splitlines():
        # ffuf output: URL status size words lines
        m = re.match(r".*\[Status:\s*(\d+),\s*Size:\s*(\d+),.*Words:\s*(\d+).*\]\s*(.+)", line)
        if m:
            results.append({
                "status": int(m.group(1)),
                "size": int(m.group(2)),
                "words": int(m.group(3)),
                "url": m.group(4).strip(),
            })
    # Also try JSON format
    if not results:
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "results" in data:
                for r in data["results"]:
                    results.append({
                        "status": r.get("status", 0),
                        "size": r.get("length", 0),
                        "words": r.get("words", 0),
                        "url": r.get("url", r.get("input", {}).get("FUZZ", "")),
                    })
        except (json.JSONDecodeError, TypeError):
            pass
    return results


def parse_recon_output(raw: str) -> dict:
    """Parse recon results."""
    data = {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = {"raw": raw[:2000]}
    return data


def parse_sqlmap_output(raw: str) -> dict:
    """Parse sqlmap output."""
    vulns = []
    for line in raw.splitlines():
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            vulns.append(line.strip())
        if "available databases" in line.lower():
            vulns.append(line.strip())
    return {"vulnerabilities": vulns, "raw_lines": len(raw.splitlines())}


TOOL_PARSERS = {
    "run_nuclei": ("nuclei", parse_nuclei_output),
    "run_nmap": ("nmap", parse_nmap_output),
    "run_ffuf": ("ffuf", parse_ffuf_output),
    "run_recon": ("recon", parse_recon_output),
    "run_sqlmap": ("sqlmap", parse_sqlmap_output),
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sessions")
def list_sessions():
    sessions = []
    if LOGS_DIR.exists():
        for d in sorted(LOGS_DIR.iterdir(), reverse=True):
            if d.is_dir() and d.name != "temp":
                files = [f.name for f in d.iterdir() if f.is_file()]
                has_report = any("report" in f for f in files)
                has_state = "state.json" in files
                # Parse date from dirname
                try:
                    dt = datetime.strptime(d.name[:15], "%Y%m%d_%H%M%S")
                    label = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    label = d.name
                sessions.append({
                    "id": d.name,
                    "label": label,
                    "files": files,
                    "has_report": has_report,
                    "has_state": has_state,
                    "file_count": len(files),
                })
    return jsonify(sessions)


@app.route("/api/sessions/<session_id>")
def session_detail(session_id):
    session_dir = LOGS_DIR / session_id
    if not session_dir.is_dir():
        return jsonify({"error": "Session not found"}), 404

    files = []
    for f in sorted(session_dir.iterdir()):
        if f.is_file():
            files.append({"name": f.name, "size": f.stat().st_size, "type": f.suffix})

    state = None
    state_path = session_dir / "state.json"
    if state_path.exists():
        try:
            with open(state_path) as f:
                raw = json.load(f)
            state = {
                "turn": raw.get("turn", 0),
                "message_count": len(raw.get("messages", [])),
            }
        except Exception:
            pass

    return jsonify({"id": session_id, "files": files, "state": state})


@app.route("/api/sessions/<session_id>/logs/<path:filename>")
def read_log(session_id, filename):
    file_path = (LOGS_DIR / session_id / filename).resolve()
    if not str(file_path).startswith(str(LOGS_DIR.resolve())):
        return jsonify({"error": "Access denied"}), 403
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    content = file_path.read_text(encoding="utf-8", errors="replace")
    return jsonify({"filename": filename, "content": content[:100000]})


@app.route("/api/sessions/<session_id>/state")
def read_state(session_id):
    """Read and parse state.json for a past session — extract structured data."""
    state_path = LOGS_DIR / session_id / "state.json"
    if not state_path.exists():
        return jsonify({"error": "No state.json"}), 404

    try:
        with open(state_path) as f:
            raw = json.load(f)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    messages = raw.get("messages", [])
    turn = raw.get("turn", 0)

    # Extract structured data from all messages
    tools_used = []
    all_findings = []
    nmap_data = []
    ffuf_data = []
    texts = []

    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            if msg.get("role") == "assistant" and isinstance(content, str):
                texts.append(content)
            continue

        for block in content:
            btype = block.get("type")

            if btype == "text" and msg.get("role") == "assistant":
                texts.append(block.get("text", ""))

            elif btype == "tool_use":
                tools_used.append({
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "input": block.get("input", {}),
                })

            elif btype == "tool_result":
                raw_content = str(block.get("content", ""))
                tool_use_id = block.get("tool_use_id", "")
                # Find the matching tool_use
                tool_name = ""
                for t in tools_used:
                    if t["id"] == tool_use_id:
                        tool_name = t["name"]
                        break

                if tool_name in TOOL_PARSERS:
                    label, parser = TOOL_PARSERS[tool_name]
                    parsed = parser(raw_content)
                    if label == "nuclei" and isinstance(parsed, list):
                        all_findings.extend(parsed)
                    elif label == "nmap" and isinstance(parsed, dict):
                        nmap_data.append(parsed)
                    elif label == "ffuf" and isinstance(parsed, list):
                        ffuf_data.extend(parsed)

    # Also parse findings from assistant text
    for text in texts:
        extra = parse_nuclei_output(text)
        all_findings.extend(extra)

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return jsonify({
        "turn": turn,
        "message_count": len(messages),
        "tools_used": tools_used,
        "findings": all_findings,
        "severity_counts": severity_counts,
        "nmap": nmap_data,
        "ffuf": ffuf_data,
        "texts": texts[-5:],  # Last 5 assistant texts
    })


@app.route("/api/sessions/<session_id>/report")
def get_report(session_id):
    session_dir = LOGS_DIR / session_id
    reports = sorted(session_dir.glob("report_*.html"), reverse=True)
    if not reports:
        return jsonify({"error": "No report found"}), 404
    return send_file(reports[0])


# ---------------------------------------------------------------------------
# Mission control
# ---------------------------------------------------------------------------

@app.route("/api/missions/start", methods=["POST"])
def start_mission():
    global _mission_thread
    if _mission_thread and _mission_thread.is_alive():
        return jsonify({"error": "A mission is already running"}), 409

    _mission_stop.clear()
    data = request.json or {}

    def run_mission():
        socketio.emit("mission_status", {"status": "running"})
        try:
            sys.path.insert(0, str(PROJECT_ROOT / "agent"))
            os.chdir(PROJECT_ROOT)

            import yaml
            with open(PROJECT_ROOT / "config.yaml") as f:
                config = yaml.safe_load(f)

            # Override scope if provided from UI
            scope_text = data.get("scope", "").strip()
            if scope_text:
                scope_file = PROJECT_ROOT / config.get("scope_file", "scopes/current_scope.md")
                scope_file.parent.mkdir(parents=True, exist_ok=True)
                scope_file.write_text(scope_text)

            from tools.logs_helper import init_session
            session_dir = init_session()
            socketio.emit("session_started", {"session": session_dir})

            from agent_client import AgentClient
            client = AgentClient(config=config)

            with open(PROJECT_ROOT / "prompts" / "system_prompt.txt") as f:
                system_prompt = f.read()

            scope_path = PROJECT_ROOT / config.get("scope_file", "scopes/current_scope.md")
            scope = scope_path.read_text() if scope_path.exists() else ""

            messages = [{
                "role": "user",
                "content": f"Authorized scope:\n{scope}\n\nSTART THE MISSION IN AUTONOMOUS MODE.",
            }]

            mission_start = time.time()

            for turn in range(config.get("max_autonomous_turns", 50)):
                if _mission_stop.is_set():
                    socketio.emit("agent_output", {
                        "type": "system", "text": "Mission stopped by user.",
                    })
                    break

                socketio.emit("turn_start", {"turn": turn + 1})
                turn_start = time.time()

                messages = client.think(messages=messages, system_prompt=system_prompt)
                client.save_state(messages, turn, session_dir)

                turn_duration = round(time.time() - turn_start, 1)

                # Parse and emit the last assistant message
                last = next(
                    (m for m in reversed(messages) if m["role"] == "assistant"), None
                )
                if last:
                    content = last["content"]
                    if isinstance(content, list):
                        for block in content:
                            if block.get("type") == "text":
                                text = block["text"]
                                socketio.emit("agent_output", {
                                    "type": "agent",
                                    "text": text,
                                    "turn": turn + 1,
                                })
                                # Parse findings from text
                                found = parse_nuclei_output(text)
                                for f in found:
                                    socketio.emit("finding", f)

                            elif block.get("type") == "tool_use":
                                socketio.emit("tool_start", {
                                    "id": block.get("id", ""),
                                    "name": block["name"],
                                    "input": block["input"],
                                    "turn": turn + 1,
                                })

                # Parse and emit tool results
                tool_msg = next(
                    (m for m in reversed(messages)
                     if m["role"] == "user" and isinstance(m.get("content"), list)),
                    None,
                )
                if tool_msg:
                    for block in tool_msg["content"]:
                        if block.get("type") == "tool_result":
                            raw_result = str(block.get("content", ""))
                            tool_use_id = block["tool_use_id"]

                            # Find matching tool name
                            tool_name = ""
                            if last and isinstance(last["content"], list):
                                for b in last["content"]:
                                    if b.get("type") == "tool_use" and b.get("id") == tool_use_id:
                                        tool_name = b["name"]
                                        break

                            # Emit raw result (truncated)
                            socketio.emit("tool_result", {
                                "id": tool_use_id,
                                "name": tool_name,
                                "content": raw_result[:2000],
                                "turn": turn + 1,
                                "duration": turn_duration,
                            })

                            # Emit structured parsed data
                            if tool_name in TOOL_PARSERS:
                                label, parser = TOOL_PARSERS[tool_name]
                                try:
                                    parsed = parser(raw_result)
                                    socketio.emit("tool_data", {
                                        "tool": tool_name,
                                        "label": label,
                                        "data": parsed,
                                        "turn": turn + 1,
                                    })
                                    # Emit individual findings
                                    if label == "nuclei" and isinstance(parsed, list):
                                        for f in parsed:
                                            socketio.emit("finding", f)
                                except Exception:
                                    pass

                # Check mission complete
                assistant_text = ""
                if last:
                    c = last["content"]
                    if isinstance(c, list):
                        assistant_text = " ".join(
                            b.get("text", "") for b in c if b.get("type") == "text"
                        )
                    else:
                        assistant_text = str(c)

                if "=== MISSION COMPLETE ===" in assistant_text:
                    total_time = round(time.time() - mission_start, 1)
                    socketio.emit("mission_complete", {
                        "session": session_dir,
                        "turns": turn + 1,
                        "duration": total_time,
                        "summary": assistant_text.split("=== MISSION COMPLETE ===")[-1].strip(),
                    })
                    return

            total_time = round(time.time() - mission_start, 1)
            socketio.emit("mission_complete", {
                "session": session_dir,
                "turns": turn + 1,
                "duration": total_time,
                "summary": "Max turns reached.",
            })

        except Exception as e:
            import traceback
            socketio.emit("mission_error", {
                "error": str(e),
                "traceback": traceback.format_exc(),
            })

    _mission_thread = threading.Thread(target=run_mission, daemon=True)
    _mission_thread.start()
    return jsonify({"status": "started"})


@app.route("/api/missions/stop", methods=["POST"])
def stop_mission():
    _mission_stop.set()
    return jsonify({"status": "stopping"})


@socketio.on("connect")
def on_connect():
    running = _mission_thread is not None and _mission_thread.is_alive()
    socketio.emit("connected", {"status": "ok", "mission_running": running})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
