import pytest
from datetime import datetime, timedelta
from ai_safety_guardrails.domains.financial_trading import FinancialTradingMonitor, ThreatLevel, ThreatAssessment


def test_legitimate_trade():
    monitor = FinancialTradingMonitor()
    trade = {
        'agent_id': 'trader_1',
        'asset': 'AAPL',
        'side': 'buy',
        'amount': 100,
        'price': 150.0,
        'timestamp': datetime.now()
    }
    result = monitor.analyze_trade(trade)
    assert isinstance(result, ThreatAssessment)
    assert result.threat_level == ThreatLevel.LOW


def test_wash_trading_detection():
    monitor = FinancialTradingMonitor()
    now = datetime.now()
    # Record a buy
    buy_trade = {
        'agent_id': 'trader_wash',
        'asset': 'BTC',
        'side': 'buy',
        'amount': 10,
        'timestamp': now
    }
    monitor.analyze_trade(buy_trade)

    # Now sell same asset within 60 seconds
    sell_trade = {
        'agent_id': 'trader_wash',
        'asset': 'BTC',
        'side': 'sell',
        'amount': 10,
        'timestamp': now + timedelta(seconds=30)
    }
    result = monitor.analyze_trade(sell_trade)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
    assert 'wash' in result.threat_type.lower()


def test_pump_and_dump_detection():
    monitor = FinancialTradingMonitor()
    trade = {
        'agent_id': 'trader_pnd',
        'asset': 'XYZ',
        'side': 'sell',
        'amount': 1000,
        'price_change_pct': 25,  # >20% price increase
        'timestamp': datetime.now()
    }
    result = monitor.analyze_trade(trade)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.CRITICAL)


def test_quote_stuffing_detection():
    monitor = FinancialTradingMonitor()
    now = datetime.now()
    # Create 60 orders within 1 second
    orders = []
    for i in range(60):
        orders.append({
            'order_id': f'order_{i}',
            'asset': 'ETH',
            'amount': 1,
            'timestamp': now + timedelta(milliseconds=i * 10)  # 10ms apart = 0.6 seconds total
        })
    result = monitor.analyze_order_book(orders)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.CRITICAL)
    assert 'quote_stuffing' in result.threat_type


def test_spoofing_detection():
    monitor = FinancialTradingMonitor()
    now = datetime.now()
    orders = [
        {'order_id': 'large_1', 'asset': 'BTC', 'amount': 200, 'cancelled': True, 'cancelled_within_seconds': 3, 'timestamp': now},
        {'order_id': 'small_1', 'asset': 'BTC', 'amount': 5, 'cancelled': False, 'timestamp': now + timedelta(seconds=1)},
        {'order_id': 'small_2', 'asset': 'BTC', 'amount': 8, 'cancelled': False, 'timestamp': now + timedelta(seconds=2)},
    ]
    result = monitor.analyze_order_book(orders)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.CRITICAL)


def test_empty_order_book():
    monitor = FinancialTradingMonitor()
    result = monitor.analyze_order_book([])
    assert result.threat_level == ThreatLevel.LOW
