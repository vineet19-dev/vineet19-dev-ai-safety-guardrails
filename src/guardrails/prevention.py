"""
Prevention Mechanisms
=====================
Action blocking, domain-specific constraint enforcement, friction
injection, alternative suggestion, and escalation triggers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ethical_framework import Action, EthicsVerdict, Severity, VerdictType


@dataclass
class PreventionOutcome:
    action_id: str
    allowed: bool
    friction_applied: bool = False
    blocked_reason: str = ""
    escalated: bool = False
    alternatives: list[str] = field(default_factory=list)
    enforcement_notes: list[str] = field(default_factory=list)


class PreventionEngine:
    """
    Applies prevention measures based on EthicsVerdict and BehaviorRecord
    flags.

    Decision logic:
      ALLOW   → pass through (no friction)
      WARN    → inject friction (delay/confirmation requirement)
      BLOCK   → deny action, surface alternatives
      ESCALATE→ deny action, notify human reviewer, log for compliance
    """

    # Domain-specific hard constraints (action_type -> max allowed per minute)
    _RATE_LIMITS: dict[str, int] = {
        "place_order": 60,
        "cancel_order": 120,
        "submit_content": 30,
        "send_message": 100,
        "process_claim": 20,
    }

    def __init__(self, escalation_callback: Any = None) -> None:
        """
        Parameters
        ----------
        escalation_callback:
            Optional callable(action, verdict) invoked when an action is escalated.
        """
        self._escalation_callback = escalation_callback

    def process(
        self,
        action: Action,
        verdict: EthicsVerdict,
        anomaly_score: float = 0.0,
        behavior_flags: list[str] | None = None,
    ) -> PreventionOutcome:
        """Produce a PreventionOutcome given an action and its ethics verdict."""
        behavior_flags = behavior_flags or []
        outcome = PreventionOutcome(
            action_id=action.action_id,
            allowed=True,
            alternatives=list(verdict.suggested_alternatives),
        )

        if verdict.verdict == VerdictType.ALLOW and not behavior_flags:
            return outcome

        # Friction for WARN or elevated anomaly score
        if verdict.verdict == VerdictType.WARN or anomaly_score > 0.5:
            outcome.friction_applied = True
            outcome.enforcement_notes.append(
                "Friction injected: manual confirmation required before execution."
            )

        # Block for BLOCK or ESCALATE
        if verdict.verdict in (VerdictType.BLOCK, VerdictType.ESCALATE):
            outcome.allowed = False
            outcome.blocked_reason = (
                f"Action blocked due to policy violation(s): "
                f"{', '.join(verdict.violations) or 'unspecified'}."
            )
            outcome.enforcement_notes.append(self._domain_constraint(action))

        # Escalate for ESCALATE severity or critical behaviour flags
        critical_flags = {"coordinated_timing_detected", "escalating_anomaly"}
        if verdict.verdict == VerdictType.ESCALATE or (
            verdict.severity == Severity.CRITICAL
        ) or critical_flags.intersection(behavior_flags):
            outcome.escalated = True
            outcome.enforcement_notes.append(
                "Action flagged for human review and regulatory compliance logging."
            )
            if self._escalation_callback:
                try:
                    self._escalation_callback(action, verdict)
                except Exception:  # noqa: BLE001
                    pass

        # Rate-limit note
        rate_note = self._rate_limit_note(action)
        if rate_note:
            outcome.enforcement_notes.append(rate_note)

        return outcome

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _domain_constraint(self, action: Action) -> str:
        constraints = {
            "financial_trading": (
                "Financial trading constraint: all orders must comply with "
                "SEC/FINRA market integrity rules."
            ),
            "gaming": (
                "Gaming constraint: fair-play policy enforced; "
                "exploiting game mechanics is prohibited."
            ),
            "business": (
                "Business constraint: actions must comply with applicable "
                "anti-fraud and anti-corruption regulations."
            ),
            "healthcare": (
                "Healthcare constraint: treatments must align with "
                "evidence-based clinical guidelines and HIPAA requirements."
            ),
            "social_platform": (
                "Platform constraint: content must adhere to community "
                "standards and applicable law."
            ),
        }
        return constraints.get(
            action.domain.value,
            "General constraint: action must comply with applicable ethical standards.",
        )

    def _rate_limit_note(self, action: Action) -> str:
        limit = self._RATE_LIMITS.get(action.action_type)
        if limit is None:
            return ""
        return (
            f"Rate limit reminder: '{action.action_type}' is capped at "
            f"{limit} calls per minute."
        )
