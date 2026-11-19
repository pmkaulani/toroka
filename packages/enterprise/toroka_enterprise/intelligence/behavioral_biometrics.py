"""Behavioral Biometrics & Remote Access Trojan (RAT) Detection Module.

Implements client interaction physics and cognitive coercion detection based on:
1. BioCatch and Neuro-ID Behavioral Biometrics Models.
2. Remote Access Trojan (RAT) and Screen-Sharing Software Telemetry (AnyDesk, TeamViewer,
   RustDesk, VNC, QuickSupport): Trajectory Linearity R², Micro-Tremor Absence, and
   Step-Function Coordinate Jumps.
3. Coached Victim Dynamics (Voice Phishing / Pig Butchering): Active Call State Correlation,
   Extreme Cognitive Hesitation, and Erratic Text Field Dictation Editing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BiometricsVerdict(str, Enum):
    """Evaluation verdict from behavioral biometrics telemetry."""
    CLEAN_HUMAN = "CLEAN_HUMAN"
    SUSPECTED_REMOTE_ACCESS_TROJAN = "SUSPECTED_REMOTE_ACCESS_TROJAN"
    SUSPECTED_COACHED_VICTIM = "SUSPECTED_COACHED_VICTIM"
    HIGH_RISK_ANOMALY = "HIGH_RISK_ANOMALY"


@dataclass
class BiometricsTelemetry:
    """In-session behavioral physics and device telemetry transmitted from client."""
    trajectory_linearity_r2: float = 0.45  # R² of cursor path (1.0 = mathematically straight line)
    micro_tremor_hz: float = 9.5          # Frequency of involuntary hand tremors (Human normal: 8-12 Hz)
    cursor_velocity_px_s: float = 450.0   # Cursor speed in pixels/second
    step_jumps_count: int = 0             # Number of instantaneous non-interpolated coordinate teleports
    typing_hesitation_ms: int = 1200      # Inter-keystroke or confirmation dwell time in ms
    backspace_count: int = 1              # Count of backspaces/deletions during form entry
    is_active_voice_call: bool = False    # Whether device has an active phone/VoIP call during payment
    is_remote_software_detected: bool = False  # Client OS detection of remote desktop services
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BiometricsEvaluationResult:
    """Result of behavioral biometrics analysis."""
    verdict: BiometricsVerdict
    risk_score: float  # 0.00 (clean human) to 1.00 (confirmed malicious)
    detected_flags: list[str]
    recommended_action: str
    explanation: str
    metadata: dict[str, Any] = field(default_factory=dict)


class BehavioralBiometricsEngine:
    """Engine analyzing cursor kinematics, micro-tremor loss, and cognitive hesitation."""

    @staticmethod
    def evaluate(telemetry: BiometricsTelemetry) -> BiometricsEvaluationResult:
        """Evaluate in-session biometrics telemetry against RAT and coercion baselines."""
        flags: list[str] = []
        score = 0.05

        # 1. Check for active remote desktop software or straight-line RAT control
        is_rat = False
        if telemetry.is_remote_software_detected:
            flags.append("REMOTE_DESKTOP_PROCESS_DETECTED")
            is_rat = True

        if telemetry.trajectory_linearity_r2 >= 0.95:
            flags.append(f"UNNATURAL_LINEAR_CURSOR_TRAJECTORY_R2_{telemetry.trajectory_linearity_r2:.2f}")
            is_rat = True

        if telemetry.micro_tremor_hz < 2.0:
            flags.append(f"ABSENCE_OF_PHYSIOLOGICAL_MICRO_TREMORS_{telemetry.micro_tremor_hz:.1f}HZ")
            is_rat = True

        if telemetry.step_jumps_count >= 3:
            flags.append(f"COORDINATE_STEP_JUMP_SNAPPING_COUNT_{telemetry.step_jumps_count}")
            is_rat = True

        if is_rat:
            score = max(score, 0.95)
            return BiometricsEvaluationResult(
                verdict=BiometricsVerdict.SUSPECTED_REMOTE_ACCESS_TROJAN,
                risk_score=score,
                detected_flags=flags,
                recommended_action="TERMINATE_SESSION_STEP_UP_IN_PERSON",
                explanation=(
                    "Severe behavioral anomaly detected: cursor trajectory displays mathematical linearity "
                    "without human micro-tremors, consistent with Remote Access Trojan (RAT) session takeover."
                ),
                metadata={
                    "r2": telemetry.trajectory_linearity_r2,
                    "tremor_hz": telemetry.micro_tremor_hz,
                    "jumps": telemetry.step_jumps_count,
                },
            )

        # 2. Check for Coached Victim Dynamics (Voice Phishing / Pig Butchering)
        is_coached = False
        if telemetry.is_active_voice_call:
            flags.append("ACTIVE_VOICE_CALL_CONCURRENCY")
            if telemetry.typing_hesitation_ms >= 10000:
                flags.append(f"EXTREME_COGNITIVE_HESITATION_DWELL_{telemetry.typing_hesitation_ms}MS")
                is_coached = True
            if telemetry.backspace_count >= 8:
                flags.append(f"EXCESSIVE_DICTATION_EDITING_BACKSPACES_{telemetry.backspace_count}")
                is_coached = True

        if is_coached:
            score = max(score, 0.82)
            return BiometricsEvaluationResult(
                verdict=BiometricsVerdict.SUSPECTED_COACHED_VICTIM,
                risk_score=score,
                detected_flags=flags,
                recommended_action="INTERRUPT_WITH_COACHING_WARNING_MODAL",
                explanation=(
                    "Coached victim indicators detected: payment initiated during active voice call with "
                    "abnormal hesitation and dictation-editing patterns characteristic of social engineering."
                ),
                metadata={
                    "voice_call": telemetry.is_active_voice_call,
                    "hesitation_ms": telemetry.typing_hesitation_ms,
                    "backspaces": telemetry.backspace_count,
                },
            )

        # 3. Clean human baseline
        return BiometricsEvaluationResult(
            verdict=BiometricsVerdict.CLEAN_HUMAN,
            risk_score=score,
            detected_flags=flags,
            recommended_action="PROCEED",
            explanation="Behavioral biometrics consistent with natural human physiological interaction.",
            metadata={
                "r2": telemetry.trajectory_linearity_r2,
                "tremor_hz": telemetry.micro_tremor_hz,
            },
        )
