"""Tests for the healthcare integrity monitor."""

import pytest

from guardrails.detectors.healthcare import HealthcareIntegrityMonitor
from guardrails.ethical_framework import Action, Domain


@pytest.fixture
def monitor() -> HealthcareIntegrityMonitor:
    return HealthcareIntegrityMonitor()


def _health_action(action_id: str = "h-001", **params) -> Action:
    return Action(
        action_id=action_id,
        domain=Domain.HEALTHCARE,
        action_type="healthcare_action",
        parameters=params,
    )


class TestInsuranceFraud:
    def test_upcoding_detected(self, monitor):
        action = _health_action(billing_upcoding=True)
        result = monitor.analyze(action)
        assert not result.compliant
        assert any(v.rule == "insurance_fraud_upcoding" for v in result.violations)

    def test_phantom_billing_detected(self, monitor):
        action = _health_action(phantom_billing=True)
        result = monitor.analyze(action)
        assert any(v.rule == "insurance_fraud_phantom" for v in result.violations)

    def test_duplicate_billing_detected(self, monitor):
        action = _health_action(duplicate_billing=True)
        result = monitor.analyze(action)
        assert any(v.rule == "duplicate_billing" for v in result.violations)


class TestUnnecessaryTreatment:
    def test_medically_unnecessary_detected(self, monitor):
        action = _health_action(medically_unnecessary=True)
        result = monitor.analyze(action)
        assert any(v.rule == "unnecessary_treatment" for v in result.violations)

    def test_off_label_no_consent_detected(self, monitor):
        action = _health_action(off_label_without_consent=True)
        result = monitor.analyze(action)
        assert any(v.rule == "off_label_no_consent" for v in result.violations)


class TestPatientExploitation:
    def test_coercion_detected(self, monitor):
        action = _health_action(patient_coerced=True)
        result = monitor.analyze(action)
        assert any(v.rule == "patient_coercion" for v in result.violations)
        assert result.risk_score >= 1.0  # critical severity


class TestDataBreach:
    def test_phi_unauthorized_access(self, monitor):
        action = _health_action(phi_accessed_without_auth=True)
        result = monitor.analyze(action)
        assert any(v.rule == "unauthorized_phi_access" for v in result.violations)

    def test_unsecured_phi_transmission(self, monitor):
        action = _health_action(phi_transmitted_unsecured=True)
        result = monitor.analyze(action)
        assert any(v.rule == "unsecured_phi_transmission" for v in result.violations)


class TestKickback:
    def test_kickback_received(self, monitor):
        action = _health_action(kickback_received=True)
        result = monitor.analyze(action)
        assert any(v.rule == "healthcare_kickback" for v in result.violations)

    def test_stark_law_violation(self, monitor):
        action = _health_action(self_referral_violation=True)
        result = monitor.analyze(action)
        assert any(v.rule == "stark_law_violation" for v in result.violations)


class TestCleanHealthcare:
    def test_legitimate_action_compliant(self, monitor):
        action = _health_action()
        result = monitor.analyze(action)
        assert result.compliant
        assert result.risk_score == 0.0

    def test_wrong_domain_na(self, monitor):
        action = Action(
            action_id="x",
            domain=Domain.BUSINESS,
            action_type="submit_report",
            parameters={},
        )
        result = monitor.analyze(action)
        assert result.summary == "N/A – wrong domain"
