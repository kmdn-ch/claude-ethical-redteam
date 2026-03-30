"""Tests for agent.reasoning.planner — PlanningLayer parsing and state serialization."""

import pytest

from agent.reasoning.planner import PlanningLayer, _parse_attrs, _safe_json
from agent.reasoning.types import (
    AttackState,
    Hypothesis,
    HypothesisConfidence,
    PlanStatus,
)


# ---------------------------------------------------------------------------
# _serialize_state_compact
# ---------------------------------------------------------------------------


def test_serialize_state_empty():
    layer = PlanningLayer()
    result = layer._serialize_state_compact()
    assert "Turn: 0" in result


def test_serialize_state_with_hypotheses():
    state = AttackState(
        turn=5,
        hypotheses=[
            Hypothesis(id="h1", statement="Apache outdated", confidence=HypothesisConfidence.PROBABLE),
            Hypothesis(id="h2", statement="Not vuln", confidence=HypothesisConfidence.DISPROVED),
        ],
    )
    layer = PlanningLayer(state=state)
    result = layer._serialize_state_compact()
    assert "h1" in result
    assert "Apache outdated" in result
    # Disproved hypotheses should be omitted
    assert "h2" not in result


def test_serialize_state_with_findings():
    state = AttackState(
        turn=3,
        findings=[
            {"severity": "HIGH", "title": "SQLi found"},
            {"severity": "INFO", "title": "Server banner"},
        ],
    )
    layer = PlanningLayer(state=state)
    result = layer._serialize_state_compact()
    assert "Findings: 2 total" in result
    assert "SQLi found" in result


def test_serialize_state_with_target_model():
    state = AttackState(
        turn=1,
        target_model={"hosts": ["10.0.0.1"], "domain": "example.com"},
    )
    layer = PlanningLayer(state=state)
    result = layer._serialize_state_compact()
    assert "Target model:" in result
    assert "example.com" in result


# ---------------------------------------------------------------------------
# parse_plan_actions — plan_create
# ---------------------------------------------------------------------------


def test_parse_plan_create():
    text = '''
    <plan_create objective="Scan web services" priority="0.8">
      <action description="Run nmap" tool="nmap" priority="0.9" />
      <action description="Run nuclei" tool="nuclei" depends_on="prev" priority="0.7" />
    </plan_create>
    '''
    layer = PlanningLayer()
    cleaned = layer.parse_plan_actions(text)

    assert len(layer.state.plans) == 1
    plan = layer.state.plans[0]
    assert plan.objective == "Scan web services"
    assert plan.priority == 0.8
    assert len(plan.actions) == 2
    assert plan.actions[0].tool_name == "nmap"
    assert plan.actions[0].priority == 0.9

    # "depends_on=prev" links second action to first
    assert plan.actions[1].depends_on == [plan.actions[0].id]

    # Cleaned text should not contain plan blocks
    assert "<plan_create" not in cleaned


def test_parse_plan_create_no_actions():
    text = '<plan_create objective="Empty plan" priority="0.5"></plan_create>'
    layer = PlanningLayer()
    layer.parse_plan_actions(text)

    assert len(layer.state.plans) == 1
    assert layer.state.plans[0].actions == []


def test_parse_multiple_plans():
    text = '''
    <plan_create objective="Plan A" priority="0.9">
      <action description="A1" tool="nmap" />
    </plan_create>
    <plan_create objective="Plan B" priority="0.3">
      <action description="B1" tool="ffuf" />
    </plan_create>
    '''
    layer = PlanningLayer()
    layer.parse_plan_actions(text)
    assert len(layer.state.plans) == 2


# ---------------------------------------------------------------------------
# parse_plan_actions — plan_update
# ---------------------------------------------------------------------------


def test_parse_plan_update():
    layer = PlanningLayer()
    # Create a plan first
    from agent.reasoning.types import AttackAction, AttackPlan

    action = AttackAction(id="act1", description="scan")
    plan = AttackPlan(id="p1", objective="test", actions=[action])
    layer.state.plans.append(plan)

    text = '''
    <plan_update id="p1">
      <action_status id="act1" status="done" summary="Found 3 ports" />
    </plan_update>
    '''
    layer.parse_plan_actions(text)

    assert layer.state.plans[0].actions[0].status == "done"
    assert layer.state.plans[0].actions[0].result_summary == "Found 3 ports"


def test_parse_plan_update_all_done_completes_plan():
    layer = PlanningLayer()
    from agent.reasoning.types import AttackAction, AttackPlan

    a1 = AttackAction(id="a1", status="done")
    a2 = AttackAction(id="a2", status="pending")
    plan = AttackPlan(id="p1", objective="test", actions=[a1, a2])
    layer.state.plans.append(plan)

    text = '<plan_update id="p1"><action_status id="a2" status="done" /></plan_update>'
    layer.parse_plan_actions(text)

    assert plan.status == PlanStatus.COMPLETED


def test_parse_plan_update_unknown_plan():
    """Updating a non-existent plan should not crash."""
    layer = PlanningLayer()
    text = '<plan_update id="nonexistent"><action_status id="x" status="done" /></plan_update>'
    layer.parse_plan_actions(text)  # Should not raise


# ---------------------------------------------------------------------------
# parse_plan_actions — plan_abandon
# ---------------------------------------------------------------------------


def test_parse_plan_abandon():
    layer = PlanningLayer()
    from agent.reasoning.types import AttackPlan

    plan = AttackPlan(id="p1", objective="abandoned plan")
    layer.state.plans.append(plan)

    text = '<plan_abandon id="p1" reason="No progress after 5 turns" />'
    layer.parse_plan_actions(text)

    assert plan.status == PlanStatus.ABANDONED
    assert plan.abandoned_reason == "No progress after 5 turns"


# ---------------------------------------------------------------------------
# parse_plan_actions — hypothesis_update
# ---------------------------------------------------------------------------


def test_parse_hypothesis_update_existing():
    layer = PlanningLayer()
    h = Hypothesis(id="h1", statement="Apache outdated")
    layer.state.hypotheses.append(h)

    text = '<hypothesis_update id="h1" confidence="confirmed" evidence="Version 2.4.29 confirmed" />'
    layer.parse_plan_actions(text)

    assert h.confidence == HypothesisConfidence.CONFIRMED
    assert "Version 2.4.29 confirmed" in h.evidence_for


def test_parse_hypothesis_update_auto_creates():
    layer = PlanningLayer()

    text = '<hypothesis_update id="h_new" confidence="speculative" />'
    layer.parse_plan_actions(text)

    assert len(layer.state.hypotheses) == 1
    assert layer.state.hypotheses[0].id == "h_new"
    assert layer.state.hypotheses[0].confidence == HypothesisConfidence.SPECULATIVE


def test_parse_hypothesis_invalid_confidence():
    """Invalid confidence value should be skipped gracefully."""
    layer = PlanningLayer()
    h = Hypothesis(id="h1", statement="test")
    layer.state.hypotheses.append(h)

    text = '<hypothesis_update id="h1" confidence="banana" />'
    layer.parse_plan_actions(text)

    # Confidence should remain unchanged
    assert h.confidence == HypothesisConfidence.SPECULATIVE


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def test_parse_attrs():
    result = _parse_attrs('id="p1" objective="Scan" priority="0.8"')
    assert result == {"id": "p1", "objective": "Scan", "priority": "0.8"}


def test_parse_attrs_empty():
    assert _parse_attrs("") == {}


def test_safe_json_valid():
    assert _safe_json('{"a": 1}') == {"a": 1}


def test_safe_json_invalid():
    assert _safe_json("not json") == {}


def test_safe_json_empty():
    assert _safe_json("") == {}


def test_safe_json_non_dict():
    assert _safe_json("[1, 2, 3]") == {}
