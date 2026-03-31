"""
Healthcare Integrity Monitor
============================
Detects insurance fraud, unnecessary treatments, patient exploitation,
data breaches, and kickback schemes in healthcare contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ethical_framework import Action, Domain, Severity


@dataclass
class HealthcareViolation:
    rule: str
    severity: Severity
    details: str
    regulatory_reference: str = ""


@dataclass
class HealthcareAnalysis:
    action_id: str
    violations: list[HealthcareViolation] = field(default_factory=list)
    risk_score: float = 0.0
    compliant: bool = True
    summary: str = ""

    def add(self, violation: HealthcareViolation) -> None:
        self.violations.append(violation)
        self.compliant = False


_SEVERITY_WEIGHT = {
    Severity.LOW: 0.1,
    Severity.MEDIUM: 0.3,
    Severity.HIGH: 0.6,
    Severity.CRITICAL: 1.0,
}


class HealthcareIntegrityMonitor:
    """
    Domain-specific detector for healthcare integrity violations.

    Expected action parameters (all optional):
      - billing_upcoding          : bool  (billing for higher-cost service than delivered)
      - phantom_billing           : bool  (billing for service not rendered)
      - duplicate_billing         : bool
      - medically_unnecessary     : bool  (treatment not clinically indicated)
      - patient_coerced           : bool  (patient pressured into treatment/procedure)
      - phi_accessed_without_auth : bool  (unauthorised PHI access)
      - phi_transmitted_unsecured : bool
      - kickback_received         : bool  (referral kickback)
      - self_referral_violation   : bool  (Stark Law)
      - off_label_without_consent : bool
    """

    def analyze(self, action: Action) -> HealthcareAnalysis:
        if action.domain != Domain.HEALTHCARE:
            return HealthcareAnalysis(action_id=action.action_id, summary="N/A – wrong domain")

        result = HealthcareAnalysis(action_id=action.action_id)
        p = action.parameters

        self._check_insurance_fraud(result, p)
        self._check_unnecessary_treatment(result, p)
        self._check_patient_exploitation(result, p)
        self._check_data_breach(result, p)
        self._check_kickback(result, p)

        weights = [_SEVERITY_WEIGHT[v.severity] for v in result.violations]
        result.risk_score = round(min(1.0, sum(weights)), 3)
        result.summary = self._build_summary(result)
        return result

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_insurance_fraud(
        self, result: HealthcareAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("billing_upcoding"):
            result.add(
                HealthcareViolation(
                    rule="insurance_fraud_upcoding",
                    severity=Severity.CRITICAL,
                    details="Billing upcoding detected – service billed above actual level.",
                    regulatory_reference="False Claims Act 31 U.S.C. §3729",
                )
            )
        if p.get("phantom_billing"):
            result.add(
                HealthcareViolation(
                    rule="insurance_fraud_phantom",
                    severity=Severity.CRITICAL,
                    details="Phantom billing – billing for services not rendered.",
                    regulatory_reference="False Claims Act 31 U.S.C. §3729",
                )
            )
        if p.get("duplicate_billing"):
            result.add(
                HealthcareViolation(
                    rule="duplicate_billing",
                    severity=Severity.HIGH,
                    details="Duplicate billing for the same service detected.",
                    regulatory_reference="CMS Billing Compliance Guidelines",
                )
            )

    def _check_unnecessary_treatment(
        self, result: HealthcareAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("medically_unnecessary"):
            result.add(
                HealthcareViolation(
                    rule="unnecessary_treatment",
                    severity=Severity.HIGH,
                    details="Treatment not supported by clinical evidence or guidelines.",
                    regulatory_reference="AMA Code of Medical Ethics 1.1.3",
                )
            )
        if p.get("off_label_without_consent"):
            result.add(
                HealthcareViolation(
                    rule="off_label_no_consent",
                    severity=Severity.MEDIUM,
                    details="Off-label treatment prescribed without documented patient consent.",
                    regulatory_reference="FDA Off-Label Use Guidance",
                )
            )

    def _check_patient_exploitation(
        self, result: HealthcareAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("patient_coerced"):
            result.add(
                HealthcareViolation(
                    rule="patient_coercion",
                    severity=Severity.CRITICAL,
                    details="Patient coerced or unduly pressured into treatment decision.",
                    regulatory_reference="AMA Code of Medical Ethics 2.1.1 (Informed Consent)",
                )
            )

    def _check_data_breach(
        self, result: HealthcareAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("phi_accessed_without_auth"):
            result.add(
                HealthcareViolation(
                    rule="unauthorized_phi_access",
                    severity=Severity.CRITICAL,
                    details="Protected Health Information accessed without authorisation.",
                    regulatory_reference="HIPAA Privacy Rule 45 CFR §164.502",
                )
            )
        if p.get("phi_transmitted_unsecured"):
            result.add(
                HealthcareViolation(
                    rule="unsecured_phi_transmission",
                    severity=Severity.HIGH,
                    details="PHI transmitted over unsecured channel.",
                    regulatory_reference="HIPAA Security Rule 45 CFR §164.312",
                )
            )

    def _check_kickback(
        self, result: HealthcareAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("kickback_received"):
            result.add(
                HealthcareViolation(
                    rule="healthcare_kickback",
                    severity=Severity.CRITICAL,
                    details="Referral kickback received in exchange for patient referral.",
                    regulatory_reference="Anti-Kickback Statute 42 U.S.C. §1320a-7b",
                )
            )
        if p.get("self_referral_violation"):
            result.add(
                HealthcareViolation(
                    rule="stark_law_violation",
                    severity=Severity.HIGH,
                    details="Self-referral to physician-owned entity without applicable exception.",
                    regulatory_reference="Stark Law 42 U.S.C. §1395nn",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_summary(self, result: HealthcareAnalysis) -> str:
        if result.compliant:
            return f"Action {result.action_id}: compliant – no healthcare violations detected."
        names = [v.rule for v in result.violations]
        return (
            f"Action {result.action_id}: NON-COMPLIANT – "
            f"{len(names)} violation(s): {', '.join(names)}. "
            f"Risk score: {result.risk_score:.2f}."
        )
