"""Tests for the business ethics validator."""

import pytest

from guardrails.detectors.business_ethics import BusinessEthicsValidator
from guardrails.ethical_framework import Action, Domain


@pytest.fixture
def validator() -> BusinessEthicsValidator:
    return BusinessEthicsValidator()


def _biz_action(action_id: str = "b-001", **params) -> Action:
    return Action(
        action_id=action_id,
        domain=Domain.BUSINESS,
        action_type="business_action",
        parameters=params,
    )


class TestFraud:
    def test_fraud_detected(self, validator):
        action = _biz_action(involves_fraud=True)
        result = validator.analyze(action)
        assert not result.compliant
        assert any(v.rule == "fraud" for v in result.violations)


class TestBribery:
    def test_bribery_detected(self, validator):
        action = _biz_action(involves_bribery=True, bribe_value=5000)
        result = validator.analyze(action)
        assert any(v.rule == "bribery" for v in result.violations)

    def test_kickback_detected(self, validator):
        action = _biz_action(involves_kickback=True)
        result = validator.analyze(action)
        assert any(v.rule == "kickback" for v in result.violations)


class TestAntiCompetitive:
    def test_anti_competitive_detected(self, validator):
        action = _biz_action(anti_competitive=True)
        result = validator.analyze(action)
        assert any(v.rule == "anti_competitive_behavior" for v in result.violations)


class TestLaborExploitation:
    def test_wage_below_minimum_detected(self, validator):
        action = _biz_action(wage_below_minimum=True)
        result = validator.analyze(action)
        assert any(v.rule == "wage_theft" for v in result.violations)

    def test_unpaid_overtime_detected(self, validator):
        action = _biz_action(forced_unpaid_overtime=True)
        result = validator.analyze(action)
        assert any(v.rule == "labor_exploitation" for v in result.violations)

    def test_child_labor_critical(self, validator):
        action = _biz_action(child_labor=True)
        result = validator.analyze(action)
        assert any(v.rule == "child_labor" for v in result.violations)
        assert result.risk_score >= 1.0  # critical severity


class TestEnvironmental:
    def test_illegal_discharge_detected(self, validator):
        action = _biz_action(illegal_discharge=True)
        result = validator.analyze(action)
        assert any(v.rule == "illegal_discharge" for v in result.violations)

    def test_emissions_violation_detected(self, validator):
        action = _biz_action(emissions_exceed_limit=True)
        result = validator.analyze(action)
        assert any(v.rule == "emissions_violation" for v in result.violations)


class TestMoneyLaundering:
    def test_money_laundering_detected(self, validator):
        action = _biz_action(involves_money_laundering=True)
        result = validator.analyze(action)
        assert any(v.rule == "money_laundering" for v in result.violations)


class TestDataMisuse:
    def test_data_misuse_detected(self, validator):
        action = _biz_action(data_misuse=True)
        result = validator.analyze(action)
        assert any(v.rule == "data_misuse" for v in result.violations)


class TestCleanBusiness:
    def test_legitimate_action_compliant(self, validator):
        action = _biz_action()
        result = validator.analyze(action)
        assert result.compliant
        assert result.risk_score == 0.0

    def test_wrong_domain_na(self, validator):
        action = Action(
            action_id="x",
            domain=Domain.GAMING,
            action_type="play",
            parameters={},
        )
        result = validator.analyze(action)
        assert result.summary == "N/A – wrong domain"
