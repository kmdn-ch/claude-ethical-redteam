"""Tests for agent.models.findings — Finding, ActionRecord, Hypothesis, TargetInfo."""

import pytest
from datetime import datetime

from agent.models.findings import (
    ActionRecord,
    Finding,
    Hypothesis,
    HypothesisConfidence,
    TargetInfo,
)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def test_finding_defaults():
    f = Finding()
    assert f.severity == "info"
    assert f.category == ""
    assert f.id  # auto-generated
    assert isinstance(f.timestamp, datetime)


def test_finding_roundtrip():
    f = Finding(
        severity="critical",
        category="cve",
        title="SQL Injection",
        target="10.0.0.1",
        evidence="error-based SQLi in /login",
        tool_source="sqlmap",
        cvss=9.8,
        cve_id="CVE-2024-0001",
        remediation="Use parameterized queries",
    )
    d = f.to_dict()
    assert d["severity"] == "critical"
    assert isinstance(d["timestamp"], str)

    restored = Finding.from_dict(d)
    assert restored.title == f.title
    assert restored.cvss == f.cvss
    assert restored.cve_id == f.cve_id
    assert isinstance(restored.timestamp, datetime)


def test_finding_from_dict_preserves_id():
    f = Finding(title="Test")
    d = f.to_dict()
    restored = Finding.from_dict(d)
    assert restored.id == f.id


def test_finding_optional_fields_none():
    f = Finding()
    d = f.to_dict()
    assert d["cvss"] is None
    assert d["cve_id"] is None
    assert d["screenshot_path"] is None


# ---------------------------------------------------------------------------
# ActionRecord
# ---------------------------------------------------------------------------


def test_action_record_defaults():
    a = ActionRecord()
    assert a.tool == ""
    assert a.success is True
    assert a.findings_produced == []


def test_action_record_roundtrip():
    a = ActionRecord(
        tool="nmap",
        parameters={"target": "10.0.0.1", "flags": "-sV"},
        result_summary="Found 3 open ports",
        findings_produced=["f1", "f2"],
        success=True,
    )
    d = a.to_dict()
    restored = ActionRecord.from_dict(d)
    assert restored.tool == "nmap"
    assert restored.parameters == {"target": "10.0.0.1", "flags": "-sV"}
    assert restored.findings_produced == ["f1", "f2"]
    assert restored.success is True


def test_action_record_failure():
    a = ActionRecord(tool="exploit", success=False, result_summary="Connection refused")
    d = a.to_dict()
    restored = ActionRecord.from_dict(d)
    assert restored.success is False


# ---------------------------------------------------------------------------
# Hypothesis
# ---------------------------------------------------------------------------


def test_hypothesis_defaults():
    h = Hypothesis()
    assert h.confidence == HypothesisConfidence.SPECULATIVE
    assert h.evidence_for == []
    assert h.evidence_against == []


def test_hypothesis_roundtrip():
    h = Hypothesis(
        statement="Target runs outdated Apache",
        confidence=HypothesisConfidence.PROBABLE,
        evidence_for=["Server header: Apache/2.4.29"],
        evidence_against=[],
        created_turn=3,
        last_updated_turn=5,
    )
    d = h.to_dict()
    assert d["confidence"] == "probable"

    restored = Hypothesis.from_dict(d)
    assert restored.statement == h.statement
    assert restored.confidence == HypothesisConfidence.PROBABLE
    assert restored.evidence_for == ["Server header: Apache/2.4.29"]


def test_hypothesis_confidence_enum():
    assert HypothesisConfidence("confirmed") == HypothesisConfidence.CONFIRMED
    assert HypothesisConfidence("disproved") == HypothesisConfidence.DISPROVED


# ---------------------------------------------------------------------------
# TargetInfo
# ---------------------------------------------------------------------------


def test_target_info_defaults():
    t = TargetInfo()
    assert t.host == ""
    assert t.ports == []
    assert t.services == {}


def test_target_info_roundtrip():
    t = TargetInfo(
        host="10.0.0.1",
        ports=[22, 80, 443],
        services={22: "ssh", 80: "http", 443: "https"},
        technologies=["Apache", "PHP"],
        os_guess="Ubuntu 20.04",
    )
    d = t.to_dict()
    # JSON keys are strings
    assert "22" in d["services"]
    assert d["services"]["22"] == "ssh"

    restored = TargetInfo.from_dict(d)
    assert restored.host == "10.0.0.1"
    assert restored.ports == [22, 80, 443]
    assert restored.services[80] == "http"
    assert restored.os_guess == "Ubuntu 20.04"


def test_target_info_empty_services_roundtrip():
    t = TargetInfo(host="10.0.0.2")
    d = t.to_dict()
    restored = TargetInfo.from_dict(d)
    assert restored.services == {}
