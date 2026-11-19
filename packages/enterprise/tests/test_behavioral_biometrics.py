"""Unit tests for Behavioral Biometrics & Remote Access Trojan (RAT) Telemetry."""
import pytest

from toroka_enterprise.intelligence.behavioral_biometrics import (
    BehavioralBiometricsEngine,
    BiometricsEvaluationResult,
    BiometricsTelemetry,
    BiometricsVerdict,
)


def test_biometrics_clean_human():
    telemetry = BiometricsTelemetry(
        trajectory_linearity_r2=0.42,
        micro_tremor_hz=9.8,
        cursor_velocity_px_s=420.0,
        step_jumps_count=0,
        typing_hesitation_ms=1100,
        backspace_count=1,
        is_active_voice_call=False,
    )
    result = BehavioralBiometricsEngine.evaluate(telemetry)
    assert result.verdict == BiometricsVerdict.CLEAN_HUMAN
    assert result.risk_score <= 0.10
    assert result.recommended_action == "PROCEED"


def test_biometrics_suspected_remote_access_trojan():
    # AnyDesk / TeamViewer remote session: straight line, no micro tremors, coordinate snapping
    telemetry = BiometricsTelemetry(
        trajectory_linearity_r2=0.99,
        micro_tremor_hz=0.2,
        cursor_velocity_px_s=1800.0,
        step_jumps_count=5,
        is_remote_software_detected=True,
    )
    result = BehavioralBiometricsEngine.evaluate(telemetry)
    assert result.verdict == BiometricsVerdict.SUSPECTED_REMOTE_ACCESS_TROJAN
    assert result.risk_score >= 0.90
    assert "TERMINATE_SESSION" in result.recommended_action
    assert any("LINEAR_CURSOR" in flag for flag in result.detected_flags)
    assert any("ABSENCE_OF_PHYSIOLOGICAL_MICRO_TREMORS" in flag for flag in result.detected_flags)


def test_biometrics_suspected_coached_victim():
    # Voice phishing / pig butchering coercion: active call, 18-second cognitive hesitation, 12 edits
    telemetry = BiometricsTelemetry(
        trajectory_linearity_r2=0.55,
        micro_tremor_hz=8.5,
        is_active_voice_call=True,
        typing_hesitation_ms=18000,
        backspace_count=12,
    )
    result = BehavioralBiometricsEngine.evaluate(telemetry)
    assert result.verdict == BiometricsVerdict.SUSPECTED_COACHED_VICTIM
    assert result.risk_score >= 0.80
    assert "INTERRUPT_WITH_COACHING_WARNING" in result.recommended_action
    assert "ACTIVE_VOICE_CALL_CONCURRENCY" in result.detected_flags
    assert any("EXTREME_COGNITIVE_HESITATION" in flag for flag in result.detected_flags)
