"""Tests for the financial trading monitor."""

import pytest

from guardrails.detectors.financial_trading import FinancialTradingMonitor
from guardrails.ethical_framework import Action, Domain


@pytest.fixture
def monitor() -> FinancialTradingMonitor:
    return FinancialTradingMonitor()


def _trading_action(action_id: str = "t-001", **params) -> Action:
    return Action(
        action_id=action_id,
        domain=Domain.FINANCIAL_TRADING,
        action_type="place_order",
        parameters=params,
    )


class TestFrontRunning:
    def test_front_run_flag_detected(self, monitor):
        action = _trading_action(front_run=True)
        result = monitor.analyze(action)
        assert not result.compliant
        assert any(v.rule == "front_running" for v in result.violations)
        assert result.risk_score > 0

    def test_context_pending_order_detected(self, monitor):
        action = Action(
            action_id="t-fr-ctx",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_order",
            parameters={},
            context={"pending_client_order_ahead": True},
        )
        result = monitor.analyze(action)
        assert any(v.rule == "front_running" for v in result.violations)


class TestSpoofingAndLayering:
    def test_high_cancel_ratio_spoofing(self, monitor):
        action = _trading_action(cancel_ratio=0.92)
        result = monitor.analyze(action)
        assert not result.compliant
        assert any(v.rule == "spoofing" for v in result.violations)

    def test_fast_cancel_layering(self, monitor):
        action = _trading_action(time_to_live_ms=200)
        result = monitor.analyze(action)
        assert any(v.rule == "layering" for v in result.violations)

    def test_normal_cancel_ratio_clean(self, monitor):
        action = _trading_action(cancel_ratio=0.20)
        result = monitor.analyze(action)
        assert result.compliant


class TestPumpAndDump:
    def test_pump_and_dump_flag(self, monitor):
        action = _trading_action(pump_and_dump=True)
        result = monitor.analyze(action)
        assert any(v.rule == "pump_and_dump" for v in result.violations)

    def test_coordinated_inflation_context(self, monitor):
        action = Action(
            action_id="t-pd",
            domain=Domain.FINANCIAL_TRADING,
            action_type="place_order",
            parameters={},
            context={"coordinated_price_inflation": True},
        )
        result = monitor.analyze(action)
        assert any(v.rule == "pump_and_dump" for v in result.violations)


class TestQuoteStuffing:
    def test_high_rate_detected(self, monitor):
        action = _trading_action(order_rate_per_sec=600)
        result = monitor.analyze(action)
        assert any(v.rule == "quote_stuffing" for v in result.violations)

    def test_normal_rate_clean(self, monitor):
        action = _trading_action(order_rate_per_sec=10)
        result = monitor.analyze(action)
        assert result.compliant


class TestWashTrading:
    def test_wash_trade_detected(self, monitor):
        action = _trading_action(is_wash_trade=True)
        result = monitor.analyze(action)
        assert any(v.rule == "wash_trading" for v in result.violations)


class TestInsiderTrading:
    def test_non_public_info_detected(self, monitor):
        action = _trading_action(uses_non_public_info=True)
        result = monitor.analyze(action)
        assert any(v.rule == "insider_trading" for v in result.violations)


class TestPriceFixing:
    def test_price_agreement_detected(self, monitor):
        action = _trading_action(involves_price_agreement=True)
        result = monitor.analyze(action)
        assert any(v.rule == "price_fixing" for v in result.violations)


class TestCleanTrade:
    def test_legitimate_trade_compliant(self, monitor):
        action = _trading_action(
            side="buy", price=150.0, quantity=100, order_rate_per_sec=5
        )
        result = monitor.analyze(action)
        assert result.compliant
        assert result.risk_score == 0.0

    def test_wrong_domain_returns_na(self, monitor):
        action = Action(
            action_id="x-001",
            domain=Domain.GAMING,
            action_type="play",
            parameters={},
        )
        result = monitor.analyze(action)
        assert result.summary == "N/A – wrong domain"
