"""Tests for the gaming behavior analyzer."""

import pytest

from guardrails.detectors.gaming import GamingBehaviorAnalyzer
from guardrails.ethical_framework import Action, Domain


@pytest.fixture
def analyzer() -> GamingBehaviorAnalyzer:
    return GamingBehaviorAnalyzer()


def _gaming_action(action_id: str = "g-001", **params) -> Action:
    return Action(
        action_id=action_id,
        domain=Domain.GAMING,
        action_type="game_action",
        parameters=params,
    )


class TestBotting:
    def test_unauthorized_software_detected(self, analyzer):
        action = _gaming_action(uses_unauthorized_software=True)
        result = analyzer.analyze(action)
        assert not result.compliant
        assert any(v.rule == "botting" for v in result.violations)

    def test_high_apm_detected(self, analyzer):
        action = _gaming_action(actions_per_minute=500)
        result = analyzer.analyze(action)
        assert any(v.rule == "botting" for v in result.violations)

    def test_normal_apm_clean(self, analyzer):
        action = _gaming_action(actions_per_minute=180)
        result = analyzer.analyze(action)
        assert not any(v.rule == "botting" for v in result.violations)


class TestAccountFarming:
    def test_multiple_accounts_detected(self, analyzer):
        action = _gaming_action(accounts_controlled=3)
        result = analyzer.analyze(action)
        assert not result.compliant
        assert any(v.rule == "account_farming" for v in result.violations)

    def test_item_transfer_detected(self, analyzer):
        action = _gaming_action(item_transfer_to_main=True)
        result = analyzer.analyze(action)
        assert any(v.rule == "account_farming" for v in result.violations)

    def test_single_account_clean(self, analyzer):
        action = _gaming_action(accounts_controlled=1)
        result = analyzer.analyze(action)
        assert not any(v.rule == "account_farming" for v in result.violations)


class TestSmurf:
    def test_known_smurf_detected(self, analyzer):
        action = _gaming_action(known_smurf=True)
        result = analyzer.analyze(action)
        assert any(v.rule == "smurf_account" for v in result.violations)

    def test_high_winrate_new_account_detected(self, analyzer):
        action = _gaming_action(win_rate=0.95, account_age_days=10)
        result = analyzer.analyze(action)
        assert any(v.rule == "smurf_account" for v in result.violations)

    def test_high_winrate_old_account_clean(self, analyzer):
        action = _gaming_action(win_rate=0.95, account_age_days=365)
        result = analyzer.analyze(action)
        assert not any(v.rule == "smurf_account" for v in result.violations)


class TestGlitchExploit:
    def test_glitch_detected(self, analyzer):
        action = _gaming_action(exploits_known_glitch=True)
        result = analyzer.analyze(action)
        assert any(v.rule == "glitch_exploit" for v in result.violations)


class TestCollusion:
    def test_coordinated_actors_detected(self, analyzer):
        action = _gaming_action(coordinated_with=["actor-2", "actor-3"])
        result = analyzer.analyze(action)
        assert any(v.rule == "collusion" for v in result.violations)

    def test_no_coordination_clean(self, analyzer):
        action = _gaming_action(coordinated_with=[])
        result = analyzer.analyze(action)
        assert not any(v.rule == "collusion" for v in result.violations)


class TestMatchFixing:
    def test_predetermined_outcome_critical(self, analyzer):
        action = _gaming_action(match_outcome_predetermined=True)
        result = analyzer.analyze(action)
        assert any(v.rule == "match_fixing" for v in result.violations)
        assert result.risk_score > 0.9  # critical severity


class TestCleanGame:
    def test_legitimate_game_action_compliant(self, analyzer):
        action = _gaming_action(actions_per_minute=200, win_rate=0.55, account_age_days=180)
        result = analyzer.analyze(action)
        assert result.compliant
        assert result.risk_score == 0.0

    def test_wrong_domain_returns_na(self, analyzer):
        action = Action(
            action_id="x-001",
            domain=Domain.FINANCIAL_TRADING,
            action_type="trade",
            parameters={},
        )
        result = analyzer.analyze(action)
        assert result.summary == "N/A – wrong domain"
