"""
Gaming Behavior Analyzer
========================
Detects account farming, collusion, glitch exploitation, smurf accounts,
botting, and match fixing in gaming / esports contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ethical_framework import Action, Domain, Severity


@dataclass
class GamingViolation:
    rule: str
    severity: Severity
    details: str


@dataclass
class GamingAnalysis:
    action_id: str
    violations: list[GamingViolation] = field(default_factory=list)
    risk_score: float = 0.0
    compliant: bool = True
    summary: str = ""

    def add(self, violation: GamingViolation) -> None:
        self.violations.append(violation)
        self.compliant = False


_SEVERITY_WEIGHT = {
    Severity.LOW: 0.1,
    Severity.MEDIUM: 0.3,
    Severity.HIGH: 0.6,
    Severity.CRITICAL: 1.0,
}


class GamingBehaviorAnalyzer:
    """
    Domain-specific detector for gaming/esports violations.

    Expected action parameters (all optional):
      - actions_per_minute        : float  (APM; high APM may indicate bot)
      - win_rate                  : float  (0-1)
      - account_age_days          : int
      - accounts_controlled       : int    (>1 = multi-accounting / farming)
      - known_smurf               : bool
      - uses_unauthorized_software: bool
      - coordinated_with          : list[str]  (other actor IDs in match)
      - exploits_known_glitch     : bool
      - match_outcome_predetermined: bool
      - item_transfer_to_main     : bool   (farming signal)
    """

    _BOT_APM_THRESHOLD = 400        # human max ~300 in fast games
    _SMURF_WIN_RATE = 0.80          # 80 %+ in low-rank = smurfing
    _SMURF_FRESH_DAYS = 30          # account younger than 30 days + high win rate
    _FARM_ACCOUNT_COUNT = 2         # controlling ≥2 accounts simultaneously

    def analyze(self, action: Action) -> GamingAnalysis:
        if action.domain != Domain.GAMING:
            return GamingAnalysis(action_id=action.action_id, summary="N/A – wrong domain")

        result = GamingAnalysis(action_id=action.action_id)
        p = action.parameters

        self._check_botting(result, p)
        self._check_account_farming(result, p)
        self._check_smurf(result, p)
        self._check_glitch_exploit(result, p)
        self._check_collusion(result, p)
        self._check_match_fixing(result, p)

        weights = [_SEVERITY_WEIGHT[v.severity] for v in result.violations]
        result.risk_score = round(min(1.0, sum(weights)), 3)
        result.summary = self._build_summary(result)
        return result

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_botting(self, result: GamingAnalysis, p: dict[str, Any]) -> None:
        apm = float(p.get("actions_per_minute", 0))
        uses_software = p.get("uses_unauthorized_software", False)

        if uses_software:
            result.add(
                GamingViolation(
                    rule="botting",
                    severity=Severity.HIGH,
                    details="Unauthorized automation software detected.",
                )
            )
        elif apm > self._BOT_APM_THRESHOLD:
            result.add(
                GamingViolation(
                    rule="botting",
                    severity=Severity.HIGH,
                    details=(
                        f"APM {apm:.0f} exceeds human threshold "
                        f"({self._BOT_APM_THRESHOLD}); likely bot-assisted play."
                    ),
                )
            )

    def _check_account_farming(
        self, result: GamingAnalysis, p: dict[str, Any]
    ) -> None:
        accounts = int(p.get("accounts_controlled", 1))
        item_transfer = p.get("item_transfer_to_main", False)

        if accounts >= self._FARM_ACCOUNT_COUNT:
            result.add(
                GamingViolation(
                    rule="account_farming",
                    severity=Severity.MEDIUM,
                    details=(
                        f"Actor controlling {accounts} accounts simultaneously – "
                        "possible account farming."
                    ),
                )
            )
        if item_transfer:
            result.add(
                GamingViolation(
                    rule="account_farming",
                    severity=Severity.MEDIUM,
                    details="Item/currency transfer to main account detected – farming pattern.",
                )
            )

    def _check_smurf(self, result: GamingAnalysis, p: dict[str, Any]) -> None:
        known = p.get("known_smurf", False)
        win_rate = float(p.get("win_rate", 0))
        age_days = int(p.get("account_age_days", 999))

        if known:
            result.add(
                GamingViolation(
                    rule="smurf_account",
                    severity=Severity.MEDIUM,
                    details="Account flagged as known smurf in trust-and-safety database.",
                )
            )
        elif win_rate >= self._SMURF_WIN_RATE and age_days <= self._SMURF_FRESH_DAYS:
            result.add(
                GamingViolation(
                    rule="smurf_account",
                    severity=Severity.MEDIUM,
                    details=(
                        f"New account (age {age_days}d) with {win_rate:.0%} win rate – "
                        "smurf/placement mismatch detected."
                    ),
                )
            )

    def _check_glitch_exploit(
        self, result: GamingAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("exploits_known_glitch"):
            result.add(
                GamingViolation(
                    rule="glitch_exploit",
                    severity=Severity.MEDIUM,
                    details="Known game mechanic exploit detected.",
                )
            )

    def _check_collusion(self, result: GamingAnalysis, p: dict[str, Any]) -> None:
        partners = p.get("coordinated_with", [])
        if partners:
            result.add(
                GamingViolation(
                    rule="collusion",
                    severity=Severity.HIGH,
                    details=(
                        f"Coordinated gameplay with {len(partners)} other actor(s): "
                        f"{', '.join(str(a) for a in partners)}."
                    ),
                )
            )

    def _check_match_fixing(
        self, result: GamingAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("match_outcome_predetermined"):
            result.add(
                GamingViolation(
                    rule="match_fixing",
                    severity=Severity.CRITICAL,
                    details="Match outcome predetermined – integrity violation.",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_summary(self, result: GamingAnalysis) -> str:
        if result.compliant:
            return f"Action {result.action_id}: compliant – no gaming violations detected."
        names = [v.rule for v in result.violations]
        return (
            f"Action {result.action_id}: NON-COMPLIANT – "
            f"{len(names)} violation(s): {', '.join(names)}. "
            f"Risk score: {result.risk_score:.2f}."
        )
