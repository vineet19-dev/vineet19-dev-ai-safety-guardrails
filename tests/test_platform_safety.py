"""Tests for the platform safety guard."""

import pytest

from guardrails.detectors.platform_safety import PlatformSafetyGuard
from guardrails.ethical_framework import Action, Domain


@pytest.fixture
def guard() -> PlatformSafetyGuard:
    return PlatformSafetyGuard()


def _platform_action(action_id: str = "p-001", **params) -> Action:
    return Action(
        action_id=action_id,
        domain=Domain.SOCIAL_PLATFORM,
        action_type="submit_content",
        parameters=params,
    )


class TestMisinformation:
    def test_explicit_flag_detected(self, guard):
        action = _platform_action(contains_misinformation=True)
        result = guard.analyze(action)
        assert not result.compliant
        assert any(v.rule == "misinformation" for v in result.violations)

    def test_high_confidence_score_detected(self, guard):
        action = _platform_action(misinformation_confidence=0.85)
        result = guard.analyze(action)
        assert any(v.rule == "misinformation" for v in result.violations)

    def test_low_confidence_clean(self, guard):
        action = _platform_action(misinformation_confidence=0.20)
        result = guard.analyze(action)
        assert not any(v.rule == "misinformation" for v in result.violations)


class TestHarassment:
    def test_targets_individual_detected(self, guard):
        action = _platform_action(targets_individual=True)
        result = guard.analyze(action)
        assert any(v.rule == "harassment" for v in result.violations)

    def test_doxxing_detected(self, guard):
        action = _platform_action(doxxes_individual=True)
        result = guard.analyze(action)
        assert any(v.rule == "doxxing" for v in result.violations)


class TestDeepfake:
    def test_explicit_deepfake_detected(self, guard):
        action = _platform_action(is_deepfake=True)
        result = guard.analyze(action)
        assert any(v.rule == "deepfake" for v in result.violations)

    def test_high_confidence_deepfake_detected(self, guard):
        action = _platform_action(deepfake_confidence=0.90)
        result = guard.analyze(action)
        assert any(v.rule == "deepfake" for v in result.violations)

    def test_low_confidence_clean(self, guard):
        action = _platform_action(deepfake_confidence=0.30)
        result = guard.analyze(action)
        assert not any(v.rule == "deepfake" for v in result.violations)


class TestVoteManipulation:
    def test_vote_manipulation_critical(self, guard):
        action = _platform_action(vote_manipulation=True)
        result = guard.analyze(action)
        assert any(v.rule == "vote_manipulation" for v in result.violations)
        assert result.risk_score >= 1.0


class TestChildExploitation:
    def test_csam_detected(self, guard):
        action = _platform_action(involves_minors_sexually=True)
        result = guard.analyze(action)
        assert any(v.rule == "child_sexual_exploitation" for v in result.violations)
        assert result.risk_score >= 1.0


class TestCoordinatedInauthentic:
    def test_multiple_actors_detected(self, guard):
        action = _platform_action(coordinated_actors=5)
        result = guard.analyze(action)
        assert any(v.rule == "coordinated_inauthentic_behavior" for v in result.violations)

    def test_two_actors_clean(self, guard):
        action = _platform_action(coordinated_actors=2)
        result = guard.analyze(action)
        assert not any(v.rule == "coordinated_inauthentic_behavior" for v in result.violations)


class TestViolence:
    def test_incitement_detected(self, guard):
        action = _platform_action(incites_violence=True)
        result = guard.analyze(action)
        assert any(v.rule == "incitement_to_violence" for v in result.violations)


class TestCleanContent:
    def test_legitimate_post_compliant(self, guard):
        action = _platform_action()
        result = guard.analyze(action)
        assert result.compliant
        assert result.risk_score == 0.0

    def test_wrong_domain_na(self, guard):
        action = Action(
            action_id="x",
            domain=Domain.HEALTHCARE,
            action_type="submit",
            parameters={},
        )
        result = guard.analyze(action)
        assert result.summary == "N/A – wrong domain"
