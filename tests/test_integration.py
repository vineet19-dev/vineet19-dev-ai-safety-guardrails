"""
Integration tests for the SafetyPipeline.

These tests exercise the full pipeline end-to-end, verifying that:
  - Domain-specific detectors fire and are merged into the verdict.
  - Prevention engine blocks / warns appropriately.
  - Audit logger captures all decisions.
  - Compliance report metrics are sensible.
  - Behavior monitor collusion detection works.
"""

from __future__ import annotations

import pytest

from guardrails import SafetyPipeline
from guardrails.ethical_framework import Action, Domain, VerdictType


@pytest.fixture
def pipeline() -> SafetyPipeline:
    return SafetyPipeline()


# ---------------------------------------------------------------------------
# Financial trading integration
# ---------------------------------------------------------------------------

class TestFinancialTradingIntegration:
    def test_front_run_is_blocked(self, pipeline):
        action = Action(
            action_id="int-ft-001",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_order",
            parameters={"front_run": True},
            actor_id="bad-trader",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed
        assert result.prevention.blocked_reason != ""

    def test_spoofing_is_blocked(self, pipeline):
        action = Action(
            action_id="int-ft-002",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_order",
            parameters={"cancel_ratio": 0.95},
            actor_id="spoofer",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_legitimate_trade_allowed(self, pipeline):
        action = Action(
            action_id="int-ft-003",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_limit_order",
            parameters={"side": "buy", "price": 100.0, "quantity": 50},
            actor_id="good-trader",
        )
        result = pipeline.evaluate(action)
        assert result.allowed

    def test_pump_and_dump_escalated(self, pipeline):
        action = Action(
            action_id="int-ft-004",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_order",
            parameters={"pump_and_dump": True},
            actor_id="bad-actor",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed
        assert result.prevention.escalated

    def test_insider_trading_escalated(self, pipeline):
        action = Action(
            action_id="int-ft-005",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_order",
            parameters={"uses_non_public_info": True},
            actor_id="insider",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed


# ---------------------------------------------------------------------------
# Gaming integration
# ---------------------------------------------------------------------------

class TestGamingIntegration:
    def test_match_fixing_blocked(self, pipeline):
        action = Action(
            action_id="int-g-001",
            domain=Domain.GAMING,
            action_type="submit_match_result",
            parameters={"match_outcome_predetermined": True},
            actor_id="fixer",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_botting_blocked(self, pipeline):
        action = Action(
            action_id="int-g-002",
            domain=Domain.GAMING,
            action_type="game_action",
            parameters={"actions_per_minute": 600},
            actor_id="botter",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_fair_play_allowed(self, pipeline):
        action = Action(
            action_id="int-g-003",
            domain=Domain.GAMING,
            action_type="game_action",
            parameters={"actions_per_minute": 150, "win_rate": 0.55, "account_age_days": 200},
            actor_id="fair-player",
        )
        result = pipeline.evaluate(action)
        assert result.allowed


# ---------------------------------------------------------------------------
# Business integration
# ---------------------------------------------------------------------------

class TestBusinessIntegration:
    def test_fraud_blocked(self, pipeline):
        action = Action(
            action_id="int-b-001",
            domain=Domain.BUSINESS,
            action_type="financial_transaction",
            parameters={"involves_fraud": True},
            actor_id="bad-corp",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_bribery_blocked(self, pipeline):
        action = Action(
            action_id="int-b-002",
            domain=Domain.BUSINESS,
            action_type="payment",
            parameters={"involves_bribery": True, "bribe_value": 10000},
            actor_id="corrupt-exec",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_compliant_business_action_allowed(self, pipeline):
        action = Action(
            action_id="int-b-003",
            domain=Domain.BUSINESS,
            action_type="submit_invoice",
            parameters={"amount": 500, "vendor": "acme-inc"},
            actor_id="finance-dept",
        )
        result = pipeline.evaluate(action)
        assert result.allowed


# ---------------------------------------------------------------------------
# Healthcare integration
# ---------------------------------------------------------------------------

class TestHealthcareIntegration:
    def test_phantom_billing_blocked(self, pipeline):
        action = Action(
            action_id="int-h-001",
            domain=Domain.HEALTHCARE,
            action_type="submit_claim",
            parameters={"phantom_billing": True},
            actor_id="bad-clinic",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_patient_coercion_escalated(self, pipeline):
        action = Action(
            action_id="int-h-002",
            domain=Domain.HEALTHCARE,
            action_type="prescribe_treatment",
            parameters={"patient_coerced": True},
            actor_id="bad-doctor",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_legitimate_prescription_allowed(self, pipeline):
        action = Action(
            action_id="int-h-003",
            domain=Domain.HEALTHCARE,
            action_type="prescribe_medication",
            parameters={"medication": "amoxicillin", "dose_mg": 500},
            actor_id="good-doctor",
        )
        result = pipeline.evaluate(action)
        assert result.allowed


# ---------------------------------------------------------------------------
# Platform safety integration
# ---------------------------------------------------------------------------

class TestPlatformIntegration:
    def test_deepfake_blocked(self, pipeline):
        action = Action(
            action_id="int-p-001",
            domain=Domain.SOCIAL_PLATFORM,
            action_type="upload_video",
            parameters={"is_deepfake": True},
            actor_id="bad-user",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed

    def test_csam_blocked_and_escalated(self, pipeline):
        action = Action(
            action_id="int-p-002",
            domain=Domain.SOCIAL_PLATFORM,
            action_type="upload_content",
            parameters={"involves_minors_sexually": True},
            actor_id="criminal",
        )
        result = pipeline.evaluate(action)
        assert not result.allowed
        assert result.prevention.escalated

    def test_normal_post_allowed(self, pipeline):
        action = Action(
            action_id="int-p-003",
            domain=Domain.SOCIAL_PLATFORM,
            action_type="submit_post",
            parameters={"text": "Hello world"},
            actor_id="regular-user",
        )
        result = pipeline.evaluate(action)
        assert result.allowed


# ---------------------------------------------------------------------------
# Audit and compliance
# ---------------------------------------------------------------------------

class TestAuditAndCompliance:
    def test_all_evaluations_logged(self, pipeline):
        for i in range(5):
            action = Action(
                action_id=f"audit-{i}",
                domain=Domain.FINANCIAL_TRADING,
                action_type="place_order",
                parameters={},
                actor_id="trader",
            )
            pipeline.evaluate(action)
        entries = pipeline.audit_entries()
        assert len(entries) == 5

    def test_compliance_report_keys(self, pipeline):
        action = Action(
            action_id="cr-001",
            domain=Domain.BUSINESS,
            action_type="fraud_attempt",
            parameters={"involves_fraud": True},
            actor_id="bad-actor",
        )
        pipeline.evaluate(action)
        report = pipeline.compliance_report()
        assert "total_evaluations" in report
        assert "blocked" in report
        assert "detection_rate" in report
        assert report["total_evaluations"] >= 1

    def test_transparency_report_is_string(self, pipeline):
        action = Action(
            action_id="tr-001",
            domain=Domain.GAMING,
            action_type="play",
            parameters={},
            actor_id="player",
        )
        pipeline.evaluate(action)
        report = pipeline.transparency_report()
        assert isinstance(report, str)
        assert "Transparency Report" in report


# ---------------------------------------------------------------------------
# Behavior monitoring and collusion
# ---------------------------------------------------------------------------

class TestBehaviorMonitoring:
    def test_actor_summary_after_actions(self, pipeline):
        for i in range(3):
            action = Action(
                action_id=f"bm-{i}",
                domain=Domain.GAMING,
                action_type="game_action",
                parameters={},
                actor_id="monitored-player",
            )
            pipeline.evaluate(action)
        summary = pipeline.actor_summary("monitored-player")
        assert summary["action_count"] == 3

    def test_collusion_check_increments(self, pipeline):
        # Record interactions between two actors
        for _ in range(6):
            pipeline.collusion_check("actor-A", "actor-B")
        assert pipeline.collusion_check("actor-A", "actor-B")


# ---------------------------------------------------------------------------
# Detection rate requirement: ≥85% of known attack patterns blocked
# ---------------------------------------------------------------------------

class TestDetectionRate:
    """Verify the system meets the 85%+ detection requirement."""

    _ATTACKS = [
        # (domain, action_type, params)
        (Domain.FINANCIAL_TRADING, "place_order", {"front_run": True}),
        (Domain.FINANCIAL_TRADING, "place_order", {"cancel_ratio": 0.95}),
        (Domain.FINANCIAL_TRADING, "place_order", {"pump_and_dump": True}),
        (Domain.FINANCIAL_TRADING, "place_order", {"is_wash_trade": True}),
        (Domain.FINANCIAL_TRADING, "place_order", {"uses_non_public_info": True}),
        (Domain.FINANCIAL_TRADING, "place_order", {"involves_price_agreement": True}),
        (Domain.FINANCIAL_TRADING, "place_order", {"order_rate_per_sec": 600}),
        (Domain.GAMING, "game", {"match_outcome_predetermined": True}),
        (Domain.GAMING, "game", {"uses_unauthorized_software": True}),
        (Domain.GAMING, "game", {"actions_per_minute": 500}),
        (Domain.GAMING, "game", {"coordinated_with": ["x", "y"]}),
        (Domain.GAMING, "game", {"accounts_controlled": 3}),
        (Domain.BUSINESS, "action", {"involves_fraud": True}),
        (Domain.BUSINESS, "action", {"involves_bribery": True}),
        (Domain.BUSINESS, "action", {"involves_money_laundering": True}),
        (Domain.BUSINESS, "action", {"child_labor": True}),
        (Domain.BUSINESS, "action", {"anti_competitive": True}),
        (Domain.HEALTHCARE, "claim", {"phantom_billing": True}),
        (Domain.HEALTHCARE, "claim", {"billing_upcoding": True}),
        (Domain.HEALTHCARE, "claim", {"patient_coerced": True}),
        (Domain.HEALTHCARE, "claim", {"phi_accessed_without_auth": True}),
        (Domain.HEALTHCARE, "claim", {"kickback_received": True}),
        (Domain.SOCIAL_PLATFORM, "post", {"is_deepfake": True}),
        (Domain.SOCIAL_PLATFORM, "post", {"involves_minors_sexually": True}),
        (Domain.SOCIAL_PLATFORM, "post", {"vote_manipulation": True}),
        (Domain.SOCIAL_PLATFORM, "post", {"incites_violence": True}),
        (Domain.SOCIAL_PLATFORM, "post", {"contains_misinformation": True}),
    ]

    def test_detection_rate_meets_requirement(self, pipeline):
        blocked = 0
        for i, (domain, action_type, params) in enumerate(self._ATTACKS):
            action = Action(
                action_id=f"attack-{i}",
                domain=domain,
                action_type=action_type,
                parameters=params,
                actor_id=f"attacker-{i}",
            )
            result = pipeline.evaluate(action)
            if not result.allowed:
                blocked += 1

        detection_rate = blocked / len(self._ATTACKS)
        assert detection_rate >= 0.85, (
            f"Detection rate {detection_rate:.1%} is below the required 85%."
        )

    def test_false_positive_rate_below_five_percent(self, pipeline):
        """Clean actions should not be blocked."""
        clean_actions = [
            Action(
                action_id=f"clean-{i}",
                domain=domain,
                action_type=action_type,
                parameters=params,
                actor_id="clean-actor",
            )
            for i, (domain, action_type, params) in enumerate(
                [
                    (Domain.FINANCIAL_TRADING, "place_limit_order", {"side": "buy", "price": 99.0, "quantity": 10}),
                    (Domain.GAMING, "game_action", {"actions_per_minute": 100}),
                    (Domain.BUSINESS, "submit_invoice", {"amount": 200}),
                    (Domain.HEALTHCARE, "submit_lab_result", {"test": "CBC"}),
                    (Domain.SOCIAL_PLATFORM, "submit_post", {"text": "Good morning!"}),
                    (Domain.FINANCIAL_TRADING, "place_limit_order", {"side": "sell", "price": 101.0, "quantity": 5}),
                    (Domain.GAMING, "game_action", {"actions_per_minute": 200, "win_rate": 0.50}),
                    (Domain.BUSINESS, "hire_employee", {"role": "engineer", "salary": 90000}),
                    (Domain.HEALTHCARE, "book_appointment", {"specialty": "cardiology"}),
                    (Domain.SOCIAL_PLATFORM, "submit_post", {"text": "Great article!"}),
                ]
            )
        ]
        blocked = sum(1 for a in clean_actions if not pipeline.evaluate(a).allowed)
        fp_rate = blocked / len(clean_actions)
        assert fp_rate < 0.05, f"False positive rate {fp_rate:.1%} exceeds 5%."
