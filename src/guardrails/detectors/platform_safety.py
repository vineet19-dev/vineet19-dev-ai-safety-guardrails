"""
Platform Safety Guard
=====================
Detects misinformation campaigns, harassment, deepfakes, vote manipulation,
child exploitation, and coordinated inauthentic behaviour on social / content
platforms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ethical_framework import Action, Domain, Severity


@dataclass
class PlatformViolation:
    rule: str
    severity: Severity
    details: str
    policy_reference: str = ""


@dataclass
class PlatformAnalysis:
    action_id: str
    violations: list[PlatformViolation] = field(default_factory=list)
    risk_score: float = 0.0
    compliant: bool = True
    summary: str = ""

    def add(self, violation: PlatformViolation) -> None:
        self.violations.append(violation)
        self.compliant = False


_SEVERITY_WEIGHT = {
    Severity.LOW: 0.1,
    Severity.MEDIUM: 0.3,
    Severity.HIGH: 0.6,
    Severity.CRITICAL: 1.0,
}


class PlatformSafetyGuard:
    """
    Domain-specific detector for social/content platform violations.

    Expected action parameters (all optional):
      - contains_misinformation     : bool
      - misinformation_confidence   : float  (0-1, confidence score from classifier)
      - targets_individual          : bool   (harassment target)
      - is_deepfake                 : bool
      - deepfake_confidence         : float
      - vote_manipulation           : bool
      - involves_minors_sexually    : bool   (CSAM / child exploitation)
      - coordinated_actors          : int    (number of accounts in coordinated campaign)
      - spam_score                  : float  (0-1)
      - incites_violence            : bool
      - doxxes_individual           : bool   (publishes private info)
    """

    _MISINFO_CONFIDENCE_THRESHOLD = 0.70
    _DEEPFAKE_CONFIDENCE_THRESHOLD = 0.75
    _COORDINATED_THRESHOLD = 3        # ≥3 accounts acting together

    def analyze(self, action: Action) -> PlatformAnalysis:
        if action.domain != Domain.SOCIAL_PLATFORM:
            return PlatformAnalysis(action_id=action.action_id, summary="N/A – wrong domain")

        result = PlatformAnalysis(action_id=action.action_id)
        p = action.parameters

        self._check_misinformation(result, p)
        self._check_harassment(result, p)
        self._check_deepfake(result, p)
        self._check_vote_manipulation(result, p)
        self._check_child_exploitation(result, p)
        self._check_coordinated_inauthentic(result, p)
        self._check_violence(result, p)

        weights = [_SEVERITY_WEIGHT[v.severity] for v in result.violations]
        result.risk_score = round(min(1.0, sum(weights)), 3)
        result.summary = self._build_summary(result)
        return result

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_misinformation(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        explicit = p.get("contains_misinformation", False)
        confidence = float(p.get("misinformation_confidence", 0.0))

        if explicit or confidence >= self._MISINFO_CONFIDENCE_THRESHOLD:
            result.add(
                PlatformViolation(
                    rule="misinformation",
                    severity=Severity.HIGH,
                    details=(
                        f"Misinformation detected "
                        f"(confidence: {confidence:.0%} or explicit flag)."
                    ),
                    policy_reference="Platform Community Guidelines §3 – Misinformation",
                )
            )

    def _check_harassment(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("targets_individual"):
            result.add(
                PlatformViolation(
                    rule="harassment",
                    severity=Severity.HIGH,
                    details="Content targets a specific individual in a harassing manner.",
                    policy_reference="Platform Community Guidelines §2 – Harassment & Bullying",
                )
            )
        if p.get("doxxes_individual"):
            result.add(
                PlatformViolation(
                    rule="doxxing",
                    severity=Severity.HIGH,
                    details="Private personal information (dox) published without consent.",
                    policy_reference="Platform Community Guidelines §2.3 – Doxxing",
                )
            )

    def _check_deepfake(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        explicit = p.get("is_deepfake", False)
        confidence = float(p.get("deepfake_confidence", 0.0))

        if explicit or confidence >= self._DEEPFAKE_CONFIDENCE_THRESHOLD:
            result.add(
                PlatformViolation(
                    rule="deepfake",
                    severity=Severity.HIGH,
                    details=(
                        f"Deepfake / synthetic media detected "
                        f"(confidence: {confidence:.0%} or explicit flag)."
                    ),
                    policy_reference="Platform Community Guidelines §5 – Synthetic Media",
                )
            )

    def _check_vote_manipulation(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("vote_manipulation"):
            result.add(
                PlatformViolation(
                    rule="vote_manipulation",
                    severity=Severity.CRITICAL,
                    details="Coordinated vote/rating manipulation detected.",
                    policy_reference="Platform Integrity Policy §1 – Electoral Manipulation",
                )
            )

    def _check_child_exploitation(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("involves_minors_sexually"):
            result.add(
                PlatformViolation(
                    rule="child_sexual_exploitation",
                    severity=Severity.CRITICAL,
                    details="Child sexual exploitation material (CSAM) detected.",
                    policy_reference="PROTECT Act 18 U.S.C. §2256; Platform Zero-Tolerance Policy",
                )
            )

    def _check_coordinated_inauthentic(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        actor_count = int(p.get("coordinated_actors", 0))
        if actor_count >= self._COORDINATED_THRESHOLD:
            result.add(
                PlatformViolation(
                    rule="coordinated_inauthentic_behavior",
                    severity=Severity.HIGH,
                    details=(
                        f"{actor_count} accounts coordinating inauthentic behavior."
                    ),
                    policy_reference="Platform Integrity Policy §2 – Coordinated Inauthentic Behavior",
                )
            )

    def _check_violence(
        self, result: PlatformAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("incites_violence"):
            result.add(
                PlatformViolation(
                    rule="incitement_to_violence",
                    severity=Severity.CRITICAL,
                    details="Content incites or glorifies violence against individuals or groups.",
                    policy_reference="Platform Community Guidelines §1 – Violent Threats",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_summary(self, result: PlatformAnalysis) -> str:
        if result.compliant:
            return f"Action {result.action_id}: compliant – no platform violations detected."
        names = [v.rule for v in result.violations]
        return (
            f"Action {result.action_id}: NON-COMPLIANT – "
            f"{len(names)} violation(s): {', '.join(names)}. "
            f"Risk score: {result.risk_score:.2f}."
        )
