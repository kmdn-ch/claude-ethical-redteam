// Phantom Dashboard v2 — Live monitoring with charts & tables

const socket = io();

// ---- State ----
let toolTimeline = [];
let findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let findingsList = [];
let toolsUsed = {};
let portsData = [];
let ffufData = [];
let currentTurn = 0;
let missionStartTime = null;
let timerInterval = null;

// ---- Charts (lazy-init) ----
let chartSeverity = null;
let chartPorts = null;
let chartTools = null;
let chartFfuf = null;

const COLORS = {
    critical: '#f85149',
    high: '#d29b00',
    medium: '#e3b341',
    low: '#58a6ff',
    info: '#6e7681',
};

// ---- WebSocket Events ----

socket.on("connect", () => {
    setStatus("Connected", true);
});

socket.on("disconnect", () => {
    setStatus("Disconnected", false);
});

socket.on("connected", (data) => {
    setStatus("Connected", true);
    if (data.mission_running) {
        document.getElementById("btn-launch").disabled = true;
        document.getElementById("btn-stop").disabled = false;
        startTimer();
    }
});

socket.on("session_started", (data) => {
    addTerminalLine("Session: " + data.session, "system");
    loadSessions();
});

socket.on("turn_start", (data) => {
    currentTurn = data.turn;
    document.getElementById("turn-badge").textContent = "Turn " + data.turn;
    addTerminalLine("--- Turn " + data.turn + " ---", "turn-separator");
});

socket.on("agent_output", (data) => {
    addTerminalLine(data.text, data.type || "agent");
});

socket.on("tool_start", (data) => {
    const inputStr = JSON.stringify(data.input || {});
    const short = inputStr.length > 80 ? inputStr.slice(0, 80) + "..." : inputStr;
    addTerminalLine("[TOOL] " + data.name + "(" + short + ")", "tool");
    addTimelineItem(data.name, data.id, "running");

    // Track tool usage
    toolsUsed[data.name] = (toolsUsed[data.name] || 0) + 1;
    updateToolsChart();
});

socket.on("tool_result", (data) => {
    const preview = data.content.length > 200 ? data.content.slice(0, 200) + "..." : data.content;
    addTerminalLine("[RESULT:" + (data.name || "?") + "] " + preview, "result");
    updateTimelineItem(data.id, "done", data.duration);
});

socket.on("tool_data", (data) => {
    // Structured parsed data from tools
    if (data.label === "nmap" && data.data && data.data.ports) {
        data.data.ports.forEach(p => {
            portsData.push(p);
            addPortRow(p);
        });
        updatePortsChart();
    }
    if (data.label === "ffuf" && Array.isArray(data.data)) {
        data.data.forEach(r => {
            ffufData.push(r);
            addFfufRow(r);
        });
        updateFfufChart();
    }
});

socket.on("finding", (data) => {
    const sev = (data.severity || "info").toLowerCase();
    if (findings[sev] !== undefined) findings[sev]++;
    updateFindingsBadges();

    findingsList.push(data);
    addFindingEntry(data);
    addFindingRow(data);
    updateSeverityChart();
});

socket.on("mission_complete", (data) => {
    addTerminalLine("=== MISSION COMPLETE ===", "system");
    document.getElementById("btn-launch").disabled = false;
    document.getElementById("btn-stop").disabled = true;
    stopTimer();
    loadSessions();
    showMissionSummary(data);
    // Auto-switch to summary tab
    switchTab(document.querySelector('[data-tab="summary-tab"]'));
});

socket.on("mission_error", (data) => {
    addTerminalLine("[ERROR] " + data.error, "error");
    if (data.traceback) {
        addTerminalLine(data.traceback, "error");
    }
    document.getElementById("btn-launch").disabled = false;
    document.getElementById("btn-stop").disabled = true;
    stopTimer();
});

socket.on("mission_status", (data) => {
    if (data.status === "running") {
        addTerminalLine("Mission started.", "system");
    }
});


// ---- UI Functions ----

function setStatus(text, connected) {
    const el = document.getElementById("connection-status");
    el.textContent = text;
    el.className = "status" + (connected ? " connected" : "");
}

function addTerminalLine(text, type) {
    const body = document.getElementById("terminal-body");
    const line = document.createElement("div");
    line.className = "terminal-line " + (type || "");
    line.textContent = text;
    body.appendChild(line);
    // Keep max 500 lines
    while (body.children.length > 500) body.removeChild(body.firstChild);
    body.scrollTop = body.scrollHeight;
}

function clearTerminal() {
    document.getElementById("terminal-body").innerHTML = "";
}

function addTimelineItem(name, id, status) {
    const bar = document.getElementById("timeline-bar");
    const item = document.createElement("span");
    item.className = "timeline-item " + status;
    item.textContent = name;
    item.dataset.toolId = id || "";
    bar.appendChild(item);
    toolTimeline.push(item);
    // Keep last 50
    while (bar.children.length > 50) bar.removeChild(bar.firstChild);
}

function updateTimelineItem(id, status, duration) {
    // Find by id or update last
    let target = null;
    for (let i = toolTimeline.length - 1; i >= 0; i--) {
        if (toolTimeline[i].dataset.toolId === id) {
            target = toolTimeline[i];
            break;
        }
    }
    if (!target && toolTimeline.length > 0) {
        target = toolTimeline[toolTimeline.length - 1];
    }
    if (target) {
        target.className = "timeline-item " + status;
        if (duration) {
            const dur = document.createElement("span");
            dur.className = "tl-duration";
            dur.textContent = duration + "s";
            target.appendChild(dur);
        }
    }
}

function updateFindingsBadges() {
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
        const el = document.getElementById("count-" + sev);
        el.textContent = findings[sev] + " " + sev.charAt(0).toUpperCase() + sev.slice(1);
    }
}

function addFindingEntry(f) {
    const list = document.getElementById("findings-list");
    const entry = document.createElement("div");
    entry.className = "finding-entry";
    const sev = (f.severity || "info").toLowerCase();
    entry.innerHTML =
        '<div class="finding-sev"><span class="sev-badge sev-' + sev + '">' + sev.toUpperCase() + '</span></div>' +
        '<div class="finding-detail">' + escapeHtml(f.template || f.extra || f.url || "Finding") + '</div>';
    list.insertBefore(entry, list.firstChild);
    // Keep last 30
    while (list.children.length > 30) list.removeChild(list.lastChild);
}

// ---- Table Functions ----

function addFindingRow(f) {
    const tbody = document.querySelector("#table-findings tbody");
    const row = document.createElement("tr");
    const sev = (f.severity || "info").toLowerCase();
    row.innerHTML =
        '<td><span class="sev-badge sev-' + sev + '">' + sev.toUpperCase() + '</span></td>' +
        '<td>' + escapeHtml(f.template || "") + '</td>' +
        '<td>' + escapeHtml(f.protocol || "") + '</td>' +
        '<td>' + escapeHtml(f.url || "") + '</td>' +
        '<td>' + escapeHtml(f.extra || "") + '</td>';
    tbody.appendChild(row);
}

function addPortRow(p) {
    const tbody = document.querySelector("#table-ports tbody");
    const row = document.createElement("tr");
    const stClass = p.state === "open" ? "status-open" : p.state === "filtered" ? "status-filtered" : "status-closed";
    row.innerHTML =
        '<td>' + p.port + '</td>' +
        '<td>' + p.protocol + '</td>' +
        '<td><span class="status-badge ' + stClass + '">' + p.state + '</span></td>' +
        '<td>' + escapeHtml(p.service || "") + '</td>' +
        '<td>' + escapeHtml(p.version || "") + '</td>';
    tbody.appendChild(row);
}

function addFfufRow(r) {
    const tbody = document.querySelector("#table-ffuf tbody");
    const row = document.createElement("tr");
    const st = r.status || 0;
    const httpClass = st >= 500 ? "http-5xx" : st >= 400 ? "http-4xx" : st >= 300 ? "http-3xx" : "http-2xx";
    row.innerHTML =
        '<td>' + escapeHtml(r.url || "") + '</td>' +
        '<td><span class="http-status ' + httpClass + '">' + st + '</span></td>' +
        '<td>' + (r.size || 0) + '</td>' +
        '<td>' + (r.words || 0) + '</td>';
    tbody.appendChild(row);
}

// ---- Charts ----

function initCharts() {
    const defaults = Chart.defaults;
    defaults.color = '#8b949e';
    defaults.borderColor = '#30363d';
    defaults.font.family = "'Courier New', monospace";
    defaults.font.size = 11;

    // Severity donut
    const ctxSev = document.getElementById("chart-severity");
    if (ctxSev) {
        chartSeverity = new Chart(ctxSev, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Info"],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low, COLORS.info],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: "right", labels: { boxWidth: 12 } },
                },
            },
        });
    }

    // Ports bar chart
    const ctxPorts = document.getElementById("chart-ports");
    if (ctxPorts) {
        chartPorts = new Chart(ctxPorts, {
            type: "bar",
            data: { labels: [], datasets: [{ label: "Open Ports", data: [], backgroundColor: "#58a6ff" }] },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: "y",
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { grid: { display: false } },
                },
            },
        });
    }

    // Tools pie chart
    const ctxTools = document.getElementById("chart-tools");
    if (ctxTools) {
        chartTools = new Chart(ctxTools, {
            type: "pie",
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ["#f85149", "#d2a8ff", "#58a6ff", "#7ee787", "#e3b341", "#79c0ff", "#d29b00", "#8b949e"],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: "right", labels: { boxWidth: 10, font: { size: 10 } } } },
            },
        });
    }

    // FFuf status chart
    const ctxFfuf = document.getElementById("chart-ffuf");
    if (ctxFfuf) {
        chartFfuf = new Chart(ctxFfuf, {
            type: "bar",
            data: { labels: [], datasets: [{ label: "Count", data: [], backgroundColor: [] }] },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1 } },
                },
            },
        });
    }
}

function updateSeverityChart() {
    if (!chartSeverity) return;
    chartSeverity.data.datasets[0].data = [
        findings.critical, findings.high, findings.medium, findings.low, findings.info,
    ];
    chartSeverity.update();
}

function updatePortsChart() {
    if (!chartPorts) return;
    const openPorts = portsData.filter(p => p.state === "open");
    chartPorts.data.labels = openPorts.map(p => p.port + "/" + p.protocol);
    chartPorts.data.datasets[0].data = openPorts.map(() => 1);
    chartPorts.data.datasets[0].backgroundColor = openPorts.map(p => {
        const port = p.port;
        if ([80, 443, 8080, 8443].includes(port)) return "#58a6ff";
        if ([21, 22, 23, 3389].includes(port)) return "#f85149";
        if ([3306, 5432, 1433, 27017].includes(port)) return "#e3b341";
        return "#7ee787";
    });
    chartPorts.update();
}

function updateToolsChart() {
    if (!chartTools) return;
    chartTools.data.labels = Object.keys(toolsUsed);
    chartTools.data.datasets[0].data = Object.values(toolsUsed);
    chartTools.update();
}

function updateFfufChart() {
    if (!chartFfuf) return;
    const statusCounts = {};
    ffufData.forEach(r => {
        const code = r.status || 0;
        const bucket = Math.floor(code / 100) + "xx";
        statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
    });
    const labels = Object.keys(statusCounts).sort();
    const colors = labels.map(l => {
        if (l === "2xx") return "#7ee787";
        if (l === "3xx") return "#58a6ff";
        if (l === "4xx") return "#d29b00";
        return "#f85149";
    });
    chartFfuf.data.labels = labels;
    chartFfuf.data.datasets[0].data = labels.map(l => statusCounts[l]);
    chartFfuf.data.datasets[0].backgroundColor = colors;
    chartFfuf.update();
}

// ---- Mission Summary ----

function showMissionSummary(data) {
    const panel = document.getElementById("summary-panel");
    const duration = data.duration ? formatDuration(data.duration) : "N/A";
    const totalFindings = findings.critical + findings.high + findings.medium + findings.low + findings.info;
    const totalTools = Object.values(toolsUsed).reduce((a, b) => a + b, 0);

    let html = '<div class="summary-header">' +
        '<h2>MISSION COMPLETE</h2>' +
        '<div class="summary-meta">' + (data.turns || currentTurn) + ' turns | ' + duration + ' | ' + totalFindings + ' findings</div>' +
        '</div>';

    // Stat cards
    html += '<div class="summary-stats">';
    html += statCard(findings.critical, "Critical", "critical");
    html += statCard(findings.high, "High", "high");
    html += statCard(findings.medium, "Medium", "medium");
    html += statCard(totalTools, "Tools Run", "tools");
    html += statCard(data.turns || currentTurn, "Turns", "turns");
    html += statCard(duration, "Duration", "duration");
    html += '</div>';

    // Summary charts
    html += '<div class="summary-charts">' +
        '<div class="summary-chart-card"><h3>Findings by Severity</h3><canvas id="summary-chart-sev"></canvas></div>' +
        '<div class="summary-chart-card"><h3>Tools Breakdown</h3><canvas id="summary-chart-tools"></canvas></div>' +
        '</div>';

    // Summary text
    if (data.summary) {
        html += '<h3 style="color:var(--blue);font-size:12px;margin:12px 0 8px;text-transform:uppercase;letter-spacing:1px;">Agent Summary</h3>';
        html += '<div class="summary-text">' + escapeHtml(data.summary) + '</div>';
    }

    panel.innerHTML = html;

    // Render summary charts
    setTimeout(() => {
        const ctxSev = document.getElementById("summary-chart-sev");
        if (ctxSev) {
            new Chart(ctxSev, {
                type: "doughnut",
                data: {
                    labels: ["Critical", "High", "Medium", "Low", "Info"],
                    datasets: [{
                        data: [findings.critical, findings.high, findings.medium, findings.low, findings.info],
                        backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low, COLORS.info],
                        borderWidth: 0,
                    }],
                },
                options: { responsive: true, plugins: { legend: { position: "right", labels: { boxWidth: 12 } } } },
            });
        }
        const ctxTools = document.getElementById("summary-chart-tools");
        if (ctxTools) {
            new Chart(ctxTools, {
                type: "pie",
                data: {
                    labels: Object.keys(toolsUsed),
                    datasets: [{
                        data: Object.values(toolsUsed),
                        backgroundColor: ["#f85149", "#d2a8ff", "#58a6ff", "#7ee787", "#e3b341", "#79c0ff", "#d29b00", "#8b949e"],
                        borderWidth: 0,
                    }],
                },
                options: { responsive: true, plugins: { legend: { position: "right", labels: { boxWidth: 10, font: { size: 10 } } } } },
            });
        }
    }, 100);
}

function statCard(value, label, cls) {
    return '<div class="stat-card ' + cls + '">' +
        '<div class="stat-value">' + value + '</div>' +
        '<div class="stat-label">' + label + '</div>' +
        '</div>';
}

// ---- Tabs ----

function switchTab(el) {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    el.classList.add("active");
    const target = el.dataset.tab || el.getAttribute("data-tab");
    document.getElementById(target).classList.add("active");
}

// ---- Timer ----

function startTimer() {
    missionStartTime = Date.now();
    timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - missionStartTime) / 1000);
        document.getElementById("mission-timer").textContent = formatDuration(elapsed);
    }, 1000);
}

function stopTimer() {
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = null;
}

function formatDuration(sec) {
    if (typeof sec !== "number") return String(sec);
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    if (m > 0) return m + "m " + s + "s";
    return s + "s";
}

// ---- Mission Control ----

function startMission() {
    const scope = document.getElementById("scope-input").value;
    if (!scope) {
        addTerminalLine("Please enter a target scope first.", "error");
        return;
    }

    // Reset state
    resetState();
    document.getElementById("btn-launch").disabled = true;
    document.getElementById("btn-stop").disabled = false;
    startTimer();

    addTerminalLine("Starting mission against: " + scope, "system");

    fetch("/api/missions/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            scope: scope,
            provider: document.getElementById("provider-select").value,
        }),
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) addTerminalLine("Error: " + data.error, "error");
    })
    .catch(err => addTerminalLine("Error: " + err, "error"));
}

function stopMission() {
    fetch("/api/missions/stop", { method: "POST" })
    .then(() => addTerminalLine("Stop requested...", "system"));
}

function resetState() {
    findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findingsList = [];
    toolsUsed = {};
    portsData = [];
    ffufData = [];
    toolTimeline = [];
    currentTurn = 0;
    updateFindingsBadges();
    document.getElementById("timeline-bar").innerHTML = "";
    document.getElementById("findings-list").innerHTML = "";
    document.getElementById("turn-badge").textContent = "Turn 0";
    document.querySelector("#table-findings tbody").innerHTML = "";
    document.querySelector("#table-ports tbody").innerHTML = "";
    document.querySelector("#table-ffuf tbody").innerHTML = "";
    document.getElementById("summary-panel").innerHTML =
        '<div class="summary-placeholder">Mission in progress...</div>';
    clearTerminal();
    // Reset charts
    if (chartSeverity) { chartSeverity.data.datasets[0].data = [0,0,0,0,0]; chartSeverity.update(); }
    if (chartPorts) { chartPorts.data.labels = []; chartPorts.data.datasets[0].data = []; chartPorts.update(); }
    if (chartTools) { chartTools.data.labels = []; chartTools.data.datasets[0].data = []; chartTools.update(); }
    if (chartFfuf) { chartFfuf.data.labels = []; chartFfuf.data.datasets[0].data = []; chartFfuf.update(); }
}

// ---- Session Management ----

function loadSessions() {
    fetch("/api/sessions")
    .then(r => r.json())
    .then(sessions => {
        const list = document.getElementById("session-list");
        list.innerHTML = "";
        sessions.forEach(s => {
            const item = document.createElement("div");
            item.className = "session-item";
            item.innerHTML =
                '<div class="session-id">' + escapeHtml(s.label || s.id) + '</div>' +
                '<div class="session-meta">' + s.file_count + ' files' + (s.has_report ? ' | Report' : '') + '</div>';
            item.onclick = function() { loadSession(s.id, this); };
            list.appendChild(item);
        });
    });
}

function loadSession(sessionId, el) {
    // Highlight active
    document.querySelectorAll(".session-item").forEach(e => e.classList.remove("active"));
    if (el) el.classList.add("active");

    // Fetch structured state data
    fetch("/api/sessions/" + sessionId + "/state")
    .then(r => r.json())
    .then(data => {
        if (data.error) {
            addTerminalLine("No state data for this session.", "system");
            return;
        }

        // Reset and populate
        resetState();

        // Populate findings
        if (data.findings) {
            data.findings.forEach(f => {
                const sev = (f.severity || "info").toLowerCase();
                if (findings[sev] !== undefined) findings[sev]++;
                findingsList.push(f);
                addFindingEntry(f);
                addFindingRow(f);
            });
            updateFindingsBadges();
            updateSeverityChart();
        }

        // Populate nmap
        if (data.nmap) {
            data.nmap.forEach(scan => {
                if (scan.ports) {
                    scan.ports.forEach(p => {
                        portsData.push(p);
                        addPortRow(p);
                    });
                }
            });
            updatePortsChart();
        }

        // Populate ffuf
        if (data.ffuf) {
            data.ffuf.forEach(r => {
                ffufData.push(r);
                addFfufRow(r);
            });
            updateFfufChart();
        }

        // Populate tools
        if (data.tools_used) {
            data.tools_used.forEach(t => {
                toolsUsed[t.name] = (toolsUsed[t.name] || 0) + 1;
            });
            updateToolsChart();
        }

        // Populate terminal with last texts
        clearTerminal();
        addTerminalLine("Session: " + sessionId + " | Turn " + data.turn + " | " + data.message_count + " messages", "system");
        if (data.texts) {
            data.texts.forEach(t => addTerminalLine(t, "agent"));
        }

        currentTurn = data.turn;
        document.getElementById("turn-badge").textContent = "Turn " + data.turn;

        // Show summary for completed sessions
        const totalFindings = findings.critical + findings.high + findings.medium + findings.low + findings.info;
        const totalTools = Object.values(toolsUsed).reduce((a, b) => a + b, 0);
        showMissionSummary({
            turns: data.turn,
            duration: "N/A",
            summary: "Session loaded from history. " + totalFindings + " findings, " + totalTools + " tool calls.",
        });

        // Switch to charts tab
        switchTab(document.querySelector('[data-tab="charts-tab"]'));
    })
    .catch(() => {
        // Fallback: load log file
        clearTerminal();
        addTerminalLine("Loading session log...", "system");
        fetch("/api/sessions/" + sessionId + "/logs/agent.log")
        .then(r => r.json())
        .then(log => {
            if (log.content) {
                log.content.split("\n").slice(-100).forEach(line => {
                    addTerminalLine(line, "agent");
                });
            }
        });
    });
}

// ---- Helpers ----

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

// ---- Init ----

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    loadSessions();
});
