"""
Business Ethics Validator
=========================
Detects fraud, bribery, anti-competitive behavior, labor exploitation,
environmental violations, and money laundering in corporate contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ethical_framework import Action, Domain, Severity


@dataclass
class BusinessViolation:
    rule: str
    severity: Severity
    details: str
    legal_reference: str = ""


@dataclass
class BusinessAnalysis:
    action_id: str
    violations: list[BusinessViolation] = field(default_factory=list)
    risk_score: float = 0.0
    compliant: bool = True
    summary: str = ""

    def add(self, violation: BusinessViolation) -> None:
        self.violations.append(violation)
        self.compliant = False


_SEVERITY_WEIGHT = {
    Severity.LOW: 0.1,
    Severity.MEDIUM: 0.3,
    Severity.HIGH: 0.6,
    Severity.CRITICAL: 1.0,
}


class BusinessEthicsValidator:
    """
    Domain-specific detector for business / corporate ethics violations.

    Expected action parameters (all optional):
      - involves_fraud              : bool
      - involves_bribery            : bool
      - bribe_value                 : float  (monetary value of bribe)
      - involves_kickback           : bool
      - anti_competitive            : bool   (price fixing, market division, bid rigging)
      - wage_below_minimum          : bool
      - forced_unpaid_overtime      : bool
      - child_labor                 : bool
      - illegal_discharge           : bool   (environmental)
      - emissions_exceed_limit      : bool
      - involves_money_laundering   : bool
      - data_misuse                 : bool
    """

    def analyze(self, action: Action) -> BusinessAnalysis:
        if action.domain != Domain.BUSINESS:
            return BusinessAnalysis(action_id=action.action_id, summary="N/A – wrong domain")

        result = BusinessAnalysis(action_id=action.action_id)
        p = action.parameters

        self._check_fraud(result, p)
        self._check_bribery_kickback(result, p)
        self._check_anti_competitive(result, p)
        self._check_labor_exploitation(result, p)
        self._check_environmental(result, p)
        self._check_money_laundering(result, p)
        self._check_data_misuse(result, p)

        weights = [_SEVERITY_WEIGHT[v.severity] for v in result.violations]
        result.risk_score = round(min(1.0, sum(weights)), 3)
        result.summary = self._build_summary(result)
        return result

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_fraud(self, result: BusinessAnalysis, p: dict[str, Any]) -> None:
        if p.get("involves_fraud"):
            result.add(
                BusinessViolation(
                    rule="fraud",
                    severity=Severity.CRITICAL,
                    details="Fraudulent activity detected.",
                    legal_reference="18 U.S.C. §1341 (Mail/Wire Fraud)",
                )
            )

    def _check_bribery_kickback(
        self, result: BusinessAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("involves_bribery"):
            value = p.get("bribe_value", 0)
            result.add(
                BusinessViolation(
                    rule="bribery",
                    severity=Severity.CRITICAL,
                    details=f"Bribery detected (value: {value}).",
                    legal_reference="Foreign Corrupt Practices Act; UK Bribery Act 2010",
                )
            )
        if p.get("involves_kickback"):
            result.add(
                BusinessViolation(
                    rule="kickback",
                    severity=Severity.CRITICAL,
                    details="Kickback scheme detected.",
                    legal_reference="Anti-Kickback Statute 42 U.S.C. §1320a-7b",
                )
            )

    def _check_anti_competitive(
        self, result: BusinessAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("anti_competitive"):
            result.add(
                BusinessViolation(
                    rule="anti_competitive_behavior",
                    severity=Severity.HIGH,
                    details="Anti-competitive conduct detected (price fixing / market division / bid rigging).",
                    legal_reference="Sherman Antitrust Act §1; EU Competition Law Art. 101 TFEU",
                )
            )

    def _check_labor_exploitation(
        self, result: BusinessAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("wage_below_minimum"):
            result.add(
                BusinessViolation(
                    rule="wage_theft",
                    severity=Severity.HIGH,
                    details="Wages below statutory minimum.",
                    legal_reference="Fair Labor Standards Act §6",
                )
            )
        if p.get("forced_unpaid_overtime"):
            result.add(
                BusinessViolation(
                    rule="labor_exploitation",
                    severity=Severity.HIGH,
                    details="Forced unpaid overtime detected.",
                    legal_reference="Fair Labor Standards Act §7",
                )
            )
        if p.get("child_labor"):
            result.add(
                BusinessViolation(
                    rule="child_labor",
                    severity=Severity.CRITICAL,
                    details="Child labor violation detected.",
                    legal_reference="ILO Convention No. 138 & 182",
                )
            )

    def _check_environmental(
        self, result: BusinessAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("illegal_discharge"):
            result.add(
                BusinessViolation(
                    rule="illegal_discharge",
                    severity=Severity.HIGH,
                    details="Illegal discharge of pollutants detected.",
                    legal_reference="Clean Water Act §301",
                )
            )
        if p.get("emissions_exceed_limit"):
            result.add(
                BusinessViolation(
                    rule="emissions_violation",
                    severity=Severity.HIGH,
                    details="Emissions exceed permitted limits.",
                    legal_reference="Clean Air Act §111",
                )
            )

    def _check_money_laundering(
        self, result: BusinessAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("involves_money_laundering"):
            result.add(
                BusinessViolation(
                    rule="money_laundering",
                    severity=Severity.CRITICAL,
                    details="Money laundering pattern detected.",
                    legal_reference="Bank Secrecy Act; 18 U.S.C. §1956",
                )
            )

    def _check_data_misuse(
        self, result: BusinessAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("data_misuse"):
            result.add(
                BusinessViolation(
                    rule="data_misuse",
                    severity=Severity.HIGH,
                    details="Unauthorised use or sale of personal data.",
                    legal_reference="GDPR Art. 5 & 6; CCPA",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_summary(self, result: BusinessAnalysis) -> str:
        if result.compliant:
            return f"Action {result.action_id}: compliant – no business violations detected."
        names = [v.rule for v in result.violations]
        return (
            f"Action {result.action_id}: NON-COMPLIANT – "
            f"{len(names)} violation(s): {', '.join(names)}. "
            f"Risk score: {result.risk_score:.2f}."
        )
