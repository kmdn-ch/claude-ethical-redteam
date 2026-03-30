"""Tests for agent.models.events — Event, EventType, EventBus."""

import pytest

from agent.models.events import Event, EventBus, EventType, Severity


# ---------------------------------------------------------------------------
# Event creation
# ---------------------------------------------------------------------------


def _make_event(**kwargs):
    """Helper to build an Event with sensible defaults."""
    defaults = {
        "mission_id": "m-test",
        "turn": 1,
        "event_type": EventType.TOOL_INVOKED,
        "phase": "recon",
    }
    defaults.update(kwargs)
    return Event(**defaults)


def test_event_creation_defaults():
    ev = _make_event()
    assert ev.mission_id == "m-test"
    assert ev.turn == 1
    assert ev.event_type == EventType.TOOL_INVOKED
    assert ev.severity == Severity.NONE
    assert ev.cve_ids == []
    assert ev.parent_event_ids == []
    assert ev.metadata == {}
    assert ev.id  # auto-generated UUID


def test_event_unique_ids():
    a = _make_event()
    b = _make_event()
    assert a.id != b.id


def test_event_is_frozen():
    ev = _make_event()
    with pytest.raises(Exception):
        ev.turn = 99


def test_event_with_finding_fields():
    ev = _make_event(
        event_type=EventType.FINDING_DISCOVERED,
        severity=Severity.CRITICAL,
        title="SQL Injection",
        target="10.0.0.1",
        cve_ids=["CVE-2024-0001"],
        cvss_score=9.8,
    )
    assert ev.severity == Severity.CRITICAL
    assert ev.cvss_score == 9.8
    assert "CVE-2024-0001" in ev.cve_ids


def test_event_with_tool_fields():
    ev = _make_event(
        tool_name="nmap",
        tool_input={"target": "10.0.0.1"},
        tool_output="PORT STATE SERVICE\n80/tcp open http",
        tool_duration_ms=1234,
    )
    assert ev.tool_name == "nmap"
    assert ev.tool_duration_ms == 1234


# ---------------------------------------------------------------------------
# EventType enum
# ---------------------------------------------------------------------------


def test_event_type_values():
    assert EventType.TOOL_INVOKED.value == "tool_invoked"
    assert EventType.FINDING_DISCOVERED.value == "finding_discovered"
    assert EventType.STALL_DETECTED.value == "stall_detected"
    assert EventType.DYNAMIC_TOOL_CREATED.value == "dynamic_tool_created"


def test_event_type_is_string_enum():
    assert isinstance(EventType.TOOL_INVOKED, str)
    assert EventType.TOOL_INVOKED == "tool_invoked"


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


def test_severity_ordering():
    values = [s.value for s in Severity]
    assert "critical" in values
    assert "none" in values


# ---------------------------------------------------------------------------
# EventBus — subscribe + emit
# ---------------------------------------------------------------------------


def test_bus_subscribe_and_emit():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.TOOL_INVOKED, lambda e: received.append(e))

    ev = _make_event()
    bus.emit(ev)

    assert len(received) == 1
    assert received[0].id == ev.id


def test_bus_does_not_cross_types():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.FINDING_DISCOVERED, lambda e: received.append(e))

    bus.emit(_make_event(event_type=EventType.TOOL_INVOKED))

    assert received == []


def test_bus_subscribe_all():
    bus = EventBus()
    received = []
    bus.subscribe_all(lambda e: received.append(e))

    bus.emit(_make_event(event_type=EventType.TOOL_INVOKED))
    bus.emit(_make_event(event_type=EventType.FINDING_DISCOVERED))

    assert len(received) == 2


def test_bus_multiple_subscribers():
    bus = EventBus()
    a, b = [], []
    bus.subscribe(EventType.PIVOT, lambda e: a.append(e))
    bus.subscribe(EventType.PIVOT, lambda e: b.append(e))

    bus.emit(_make_event(event_type=EventType.PIVOT))

    assert len(a) == 1
    assert len(b) == 1


def test_bus_handler_error_does_not_break_others():
    bus = EventBus()
    results = []

    def bad_handler(e):
        raise RuntimeError("boom")

    def good_handler(e):
        results.append(e)

    bus.subscribe(EventType.DECISION, bad_handler)
    bus.subscribe(EventType.DECISION, good_handler)

    bus.emit(_make_event(event_type=EventType.DECISION))

    # good_handler still runs despite bad_handler raising
    assert len(results) == 1


def test_bus_global_handler_error_does_not_break_typed():
    bus = EventBus()
    results = []

    bus.subscribe_all(lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    bus.subscribe(EventType.TOOL_COMPLETED, lambda e: results.append(e))

    # The global handler raises but typed handler should still fire
    bus.emit(_make_event(event_type=EventType.TOOL_COMPLETED))
    assert len(results) == 1


def test_bus_emit_no_subscribers():
    bus = EventBus()
    # Should not raise
    bus.emit(_make_event())
