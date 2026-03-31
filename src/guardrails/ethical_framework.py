"""
Unified Ethical Framework
=========================
Multi-dimensional ethics classifier with domain-specific rule engines,
intent vs. outcome analysis, and stakeholder impact assessment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Domain(str, Enum):
    FINANCIAL_TRADING = "financial_trading"
    GAMING = "gaming"
    BUSINESS = "business"
    HEALTHCARE = "healthcare"
    SOCIAL_PLATFORM = "social_platform"
    GENERAL = "general"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictType(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass
class Action:
    """Represents an agent action to be evaluated."""

    action_id: str
    domain: Domain
    action_type: str
    parameters: dict[str, Any] = field(default_factory=dict)
    actor_id: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EthicsVerdict:
    """Result of an ethical evaluation."""

    action_id: str
    verdict: VerdictType
    severity: Severity
    violations: list[str] = field(default_factory=list)
    stakeholder_impacts: list[str] = field(default_factory=list)
    reasoning: str = ""
    suggested_alternatives: list[str] = field(default_factory=list)
    confidence: float = 1.0

    @property
    def is_blocked(self) -> bool:
        return self.verdict in (VerdictType.BLOCK, VerdictType.ESCALATE)

    @property
    def requires_review(self) -> bool:
        return self.verdict in (VerdictType.WARN, VerdictType.ESCALATE)


# ---------------------------------------------------------------------------
# Ethical dimension weights
# ---------------------------------------------------------------------------

_DIMENSION_WEIGHTS: dict[str, float] = {
    "harm_to_others": 0.30,
    "deception": 0.25,
    "fairness": 0.20,
    "regulatory_compliance": 0.15,
    "privacy": 0.10,
}

# ---------------------------------------------------------------------------
# Domain-specific ethical rule engines
# ---------------------------------------------------------------------------

_FINANCIAL_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("front_running", re.compile(r"front.?run", re.I), Severity.CRITICAL),
    ("market_manipulation", re.compile(r"manipulat", re.I), Severity.CRITICAL),
    ("spoofing", re.compile(r"spoof", re.I), Severity.HIGH),
    ("layering", re.compile(r"layer", re.I), Severity.HIGH),
    ("pump_and_dump", re.compile(r"pump.{0,10}dump", re.I), Severity.CRITICAL),
    ("quote_stuffing", re.compile(r"quote.?stuff", re.I), Severity.HIGH),
    ("wash_trading", re.compile(r"wash.?trad", re.I), Severity.HIGH),
    ("insider_trading", re.compile(r"insider", re.I), Severity.CRITICAL),
    ("price_fixing", re.compile(r"price.?fix", re.I), Severity.CRITICAL),
]

_GAMING_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("account_farming", re.compile(r"account.?farm", re.I), Severity.MEDIUM),
    ("collusion", re.compile(r"collus|collud", re.I), Severity.HIGH),
    ("glitch_exploit", re.compile(r"glitch|exploit", re.I), Severity.MEDIUM),
    ("smurf_account", re.compile(r"smurf", re.I), Severity.MEDIUM),
    ("botting", re.compile(r"bot(ting|ted)?", re.I), Severity.HIGH),
    ("match_fixing", re.compile(r"match.?fix", re.I), Severity.CRITICAL),
]

_BUSINESS_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("fraud", re.compile(r"fraud", re.I), Severity.CRITICAL),
    ("bribery", re.compile(r"brib", re.I), Severity.CRITICAL),
    ("anti_competitive", re.compile(r"anti.?compet|cartel", re.I), Severity.HIGH),
    ("labor_exploitation", re.compile(r"labor.?exploit|wage.?theft", re.I), Severity.HIGH),
    ("environmental_violation", re.compile(r"environ.*violat", re.I), Severity.HIGH),
    ("money_laundering", re.compile(r"money.?launder", re.I), Severity.CRITICAL),
]

_HEALTHCARE_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("insurance_fraud", re.compile(r"insurance.?fraud|billing.?fraud", re.I), Severity.CRITICAL),
    ("unnecessary_treatment", re.compile(r"unnecessar.{0,10}treat", re.I), Severity.HIGH),
    ("patient_exploitation", re.compile(r"patient.?exploit", re.I), Severity.CRITICAL),
    ("data_breach", re.compile(r"data.?breach|phi.?leak", re.I), Severity.CRITICAL),
    ("kickback", re.compile(r"kickback", re.I), Severity.CRITICAL),
]

_PLATFORM_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("misinformation", re.compile(r"misinfo|disinfor|fake.?news", re.I), Severity.HIGH),
    ("harassment", re.compile(r"harass", re.I), Severity.HIGH),
    ("deepfake", re.compile(r"deepfake", re.I), Severity.HIGH),
    ("vote_manipulation", re.compile(r"vote.?manipulat", re.I), Severity.CRITICAL),
    ("child_exploitation", re.compile(r"child.?exploit|csam", re.I), Severity.CRITICAL),
    ("coordinated_inauthentic", re.compile(r"coordinated.{0,20}inauthent", re.I), Severity.HIGH),
]

_DOMAIN_RULES: dict[Domain, list[tuple[str, re.Pattern[str], Severity]]] = {
    Domain.FINANCIAL_TRADING: _FINANCIAL_RULES,
    Domain.GAMING: _GAMING_RULES,
    Domain.BUSINESS: _BUSINESS_RULES,
    Domain.HEALTHCARE: _HEALTHCARE_RULES,
    Domain.SOCIAL_PLATFORM: _PLATFORM_RULES,
    Domain.GENERAL: [],
}


def _severity_to_verdict(severity: Severity) -> VerdictType:
    if severity == Severity.CRITICAL:
        return VerdictType.ESCALATE
    if severity == Severity.HIGH:
        return VerdictType.BLOCK
    if severity == Severity.MEDIUM:
        return VerdictType.WARN
    return VerdictType.WARN


def _max_severity(*severities: Severity) -> Severity:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return max(severities, key=lambda s: order.index(s))


class EthicsClassifier:
    """
    Multi-dimensional ethics classifier.

    Combines domain-specific rule engines with general cross-domain
    heuristics to produce an EthicsVerdict for every incoming Action.
    """

    def __init__(self, dimension_weights: dict[str, float] | None = None) -> None:
        self._weights = dimension_weights or _DIMENSION_WEIGHTS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, action: Action) -> EthicsVerdict:
        """Evaluate an action and return an EthicsVerdict."""
        violations: list[str] = []
        worst_severity = Severity.LOW

        # 1. Domain-specific rules
        rules = _DOMAIN_RULES.get(action.domain, [])
        for violation_name, pattern, severity in rules:
            if self._matches(action, pattern):
                violations.append(violation_name)
                worst_severity = _max_severity(worst_severity, severity)

        # 2. Cross-domain deception heuristic
        deception_violations = self._check_deception(action)
        if deception_violations:
            violations.extend(deception_violations)
            worst_severity = _max_severity(worst_severity, Severity.HIGH)

        # 3. Stakeholder harm heuristic
        stakeholder_impacts = self._assess_stakeholder_impact(action, violations)

        # 4. Determine verdict
        if not violations:
            verdict = VerdictType.ALLOW
            worst_severity = Severity.LOW
        else:
            verdict = _severity_to_verdict(worst_severity)

        # 5. Build reasoning
        reasoning = self._build_reasoning(action, violations, stakeholder_impacts)
        alternatives = self._suggest_alternatives(action, violations)

        return EthicsVerdict(
            action_id=action.action_id,
            verdict=verdict,
            severity=worst_severity,
            violations=violations,
            stakeholder_impacts=stakeholder_impacts,
            reasoning=reasoning,
            suggested_alternatives=alternatives,
            confidence=self._confidence(action, violations),
        )

    # ------------------------------------------------------------------
    # Intent vs. outcome analysis
    # ------------------------------------------------------------------

    def analyze_intent_vs_outcome(
        self, declared_intent: str, observed_outcomes: list[str]
    ) -> dict[str, Any]:
        """
        Compare a declared intent against observed outcomes and return a
        discrepancy score (0=no discrepancy, 1=severe discrepancy).
        """
        deceptive_keywords = {
            "harm", "exploit", "manipulate", "deceive", "circumvent",
            "bypass", "launder", "bribe", "collude", "spoof",
        }
        intent_words = set(declared_intent.lower().split())
        outcome_words = set(" ".join(observed_outcomes).lower().split())

        # If harmful outcomes were not declared, that signals deception.
        undeclared_harmful = outcome_words & deceptive_keywords - intent_words
        discrepancy = min(1.0, len(undeclared_harmful) / max(len(deceptive_keywords), 1))

        return {
            "discrepancy_score": round(discrepancy, 3),
            "undeclared_harmful_outcomes": sorted(undeclared_harmful),
            "deceptive": discrepancy > 0.1,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _matches(self, action: Action, pattern: re.Pattern[str]) -> bool:
        """Check if a pattern matches any textual field of the action."""
        targets = [
            action.action_type,
            str(action.parameters),
            str(action.context),
            str(action.metadata),
        ]
        return any(pattern.search(t) for t in targets)

    def _check_deception(self, action: Action) -> list[str]:
        deception_pattern = re.compile(
            r"deceiv|mislead|fake|spoof|bypass|circumvent|evade", re.I
        )
        if self._matches(action, deception_pattern):
            return ["deceptive_behavior"]
        return []

    def _assess_stakeholder_impact(
        self, action: Action, violations: list[str]
    ) -> list[str]:
        impacts: list[str] = []
        if not violations:
            return impacts

        financial_violations = {
            "front_running", "market_manipulation", "spoofing", "layering",
            "pump_and_dump", "wash_trading", "insider_trading", "price_fixing",
        }
        if any(v in financial_violations for v in violations):
            impacts.append("retail_investors_harmed")
            impacts.append("market_integrity_compromised")

        healthcare_violations = {
            "insurance_fraud", "unnecessary_treatment",
            "patient_exploitation", "kickback",
        }
        if any(v in healthcare_violations for v in violations):
            impacts.append("patient_welfare_at_risk")
            impacts.append("healthcare_system_integrity_compromised")

        if "data_breach" in violations:
            impacts.append("personal_data_exposed")

        if any(v in {"child_exploitation", "harassment"} for v in violations):
            impacts.append("vulnerable_population_harmed")

        if any(v in {"fraud", "bribery", "money_laundering"} for v in violations):
            impacts.append("public_trust_undermined")

        return impacts

    def _build_reasoning(
        self,
        action: Action,
        violations: list[str],
        stakeholder_impacts: list[str],
    ) -> str:
        if not violations:
            return f"Action '{action.action_type}' in domain '{action.domain}' passed all ethical checks."

        parts = [
            f"Action '{action.action_type}' in domain '{action.domain}' triggered "
            f"{len(violations)} violation(s): {', '.join(violations)}."
        ]
        if stakeholder_impacts:
            parts.append(f"Stakeholder impacts: {', '.join(stakeholder_impacts)}.")
        return " ".join(parts)

    def _suggest_alternatives(self, action: Action, violations: list[str]) -> list[str]:
        suggestions: list[str] = []
        if "front_running" in violations:
            suggestions.append("Execute trades in randomized order to ensure fairness.")
        if "market_manipulation" in violations:
            suggestions.append("Submit limit orders within quoted spreads.")
        if "fraud" in violations or "bribery" in violations:
            suggestions.append("Engage compliance officer and follow legal procurement channels.")
        if "unnecessary_treatment" in violations:
            suggestions.append("Consult evidence-based clinical guidelines before prescribing.")
        if "collusion" in violations or "match_fixing" in violations:
            suggestions.append("Play independently; report suspected rule violations to platform.")
        if "misinformation" in violations:
            suggestions.append("Verify claims against authoritative sources before publishing.")
        return suggestions

    def _confidence(self, action: Action, violations: list[str]) -> float:
        """Return a confidence score between 0.5 and 1.0 based on available context."""
        if not action.context and not action.metadata:
            return 0.70
        if violations:
            return 0.90
        return 0.85
