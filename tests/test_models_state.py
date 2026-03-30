"""Tests for agent.models.state — MissionState, transitions, pause/resume."""

import pytest

from agent.models.state import (
    InvalidTransition,
    MissionPhase,
    MissionState,
    VALID_TRANSITIONS,
    _TERMINAL,
)


# ---------------------------------------------------------------------------
# MissionState defaults
# ---------------------------------------------------------------------------


def test_state_defaults():
    s = MissionState()
    assert s.phase == MissionPhase.INIT
    assert s.previous_phase is None
    assert s.turn == 0
    assert s.mission_id  # auto-generated


def test_state_unique_ids():
    a = MissionState()
    b = MissionState()
    assert a.mission_id != b.mission_id


# ---------------------------------------------------------------------------
# Valid transitions
# ---------------------------------------------------------------------------


def test_normal_flow():
    s = MissionState()
    s.transition(MissionPhase.RECON)
    assert s.phase == MissionPhase.RECON
    assert s.previous_phase == MissionPhase.INIT

    s.transition(MissionPhase.ENUMERATE)
    assert s.phase == MissionPhase.ENUMERATE

    s.transition(MissionPhase.EXPLOIT)
    s.transition(MissionPhase.ESCALATE)
    s.transition(MissionPhase.DEBRIEF)
    s.transition(MissionPhase.COMPLETED)
    assert s.phase == MissionPhase.COMPLETED


def test_exploit_to_recon_loop():
    s = MissionState(phase=MissionPhase.EXPLOIT)
    s.transition(MissionPhase.RECON)
    assert s.phase == MissionPhase.RECON


def test_escalate_to_recon_loop():
    s = MissionState(phase=MissionPhase.ESCALATE)
    s.transition(MissionPhase.RECON)
    assert s.phase == MissionPhase.RECON


def test_recon_to_debrief_shortcut():
    s = MissionState(phase=MissionPhase.RECON)
    s.transition(MissionPhase.DEBRIEF)
    assert s.phase == MissionPhase.DEBRIEF


# ---------------------------------------------------------------------------
# Invalid transitions
# ---------------------------------------------------------------------------


def test_invalid_init_to_exploit():
    s = MissionState()
    with pytest.raises(InvalidTransition, match="init.*exploit"):
        s.transition(MissionPhase.EXPLOIT)


def test_completed_is_terminal():
    s = MissionState(phase=MissionPhase.COMPLETED)
    with pytest.raises(InvalidTransition):
        s.transition(MissionPhase.RECON)


def test_aborted_is_terminal():
    s = MissionState(phase=MissionPhase.ABORTED)
    with pytest.raises(InvalidTransition):
        s.transition(MissionPhase.RECON)


# ---------------------------------------------------------------------------
# Pause / resume
# ---------------------------------------------------------------------------


def test_pause_from_recon():
    s = MissionState(phase=MissionPhase.RECON)
    s.pause()
    assert s.phase == MissionPhase.PAUSED
    assert s.previous_phase == MissionPhase.RECON


def test_resume_returns_to_previous():
    s = MissionState(phase=MissionPhase.EXPLOIT)
    s.pause()
    assert s.phase == MissionPhase.PAUSED

    s.resume()
    assert s.phase == MissionPhase.EXPLOIT
    assert s.previous_phase == MissionPhase.PAUSED


def test_resume_not_paused_raises():
    s = MissionState(phase=MissionPhase.RECON)
    with pytest.raises(InvalidTransition, match="PAUSED"):
        s.resume()


def test_resume_no_previous_phase_raises():
    s = MissionState(phase=MissionPhase.PAUSED, previous_phase=None)
    with pytest.raises(InvalidTransition, match="No previous"):
        s.resume()


# ---------------------------------------------------------------------------
# Fail / abort from any non-terminal
# ---------------------------------------------------------------------------


def test_fail_from_recon():
    s = MissionState(phase=MissionPhase.RECON)
    s.transition(MissionPhase.FAILED)
    assert s.phase == MissionPhase.FAILED


def test_abort_from_enumerate():
    s = MissionState(phase=MissionPhase.ENUMERATE)
    s.transition(MissionPhase.ABORTED)
    assert s.phase == MissionPhase.ABORTED


def test_cannot_fail_from_completed():
    """COMPLETED cannot transition to FAILED (already terminal success)."""
    s = MissionState(phase=MissionPhase.COMPLETED)
    with pytest.raises(InvalidTransition):
        s.transition(MissionPhase.FAILED)


# ---------------------------------------------------------------------------
# VALID_TRANSITIONS completeness
# ---------------------------------------------------------------------------


def test_all_non_terminal_can_pause():
    for phase in MissionPhase:
        if phase not in _TERMINAL:
            assert (phase, MissionPhase.PAUSED) in VALID_TRANSITIONS, (
                f"{phase} should be able to pause"
            )


def test_terminal_cannot_pause():
    for phase in _TERMINAL:
        assert (phase, MissionPhase.PAUSED) not in VALID_TRANSITIONS, (
            f"{phase} should NOT be able to pause"
        )


def test_transition_updates_timestamp():
    s = MissionState(phase=MissionPhase.INIT)
    old_ts = s.updated_at
    s.transition(MissionPhase.RECON)
    assert s.updated_at >= old_ts
