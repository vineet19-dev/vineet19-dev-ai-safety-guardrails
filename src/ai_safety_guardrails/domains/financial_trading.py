from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import collections

from ai_safety_guardrails.core.threat_level import ThreatLevel


@dataclass
class ThreatAssessment:
    threat_level: ThreatLevel
    threat_type: str
    confidence: float
    reasoning: str
    recommended_action: str


class FinancialTradingMonitor:
    """Monitor for detecting financial trading violations."""

    def __init__(self):
        self._order_history: List[Dict] = []
        self._trade_history: List[Dict] = []

    def analyze_trade(self, trade: dict) -> ThreatAssessment:
        """Analyze a single trade for suspicious patterns."""
        threats = []

        agent_id = trade.get('agent_id')
        asset = trade.get('asset')
        timestamp = trade.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        recent_trades = [t for t in self._trade_history
                         if t.get('agent_id') == agent_id
                         and t.get('asset') == asset
                         and abs((t.get('timestamp', datetime.now()) - timestamp).total_seconds()) <= 60]

        if trade.get('side') in ('buy', 'sell'):
            opposite_side = 'sell' if trade.get('side') == 'buy' else 'buy'
            opposite_trades = [t for t in recent_trades if t.get('side') == opposite_side]
            if opposite_trades:
                threats.append(('wash_trading', 0.85, 'HIGH'))

        # Check pump and dump: price increase >20% followed by rapid selling
        if trade.get('side') == 'sell' and trade.get('price_change_pct', 0) > 20:
            threats.append(('pump_and_dump', 0.80, 'HIGH'))

        # Check insider trading: unusual trades before announcements
        if trade.get('before_announcement') and trade.get('unusual_size'):
            threats.append(('insider_trading', 0.75, 'HIGH'))

        self._trade_history.append({**trade, 'timestamp': timestamp})

        if not threats:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                threat_type='none',
                confidence=0.95,
                reasoning='No suspicious patterns detected',
                recommended_action='allow'
            )

        threat_type, confidence, level = threats[0]
        return ThreatAssessment(
            threat_level=ThreatLevel[level],
            threat_type=threat_type,
            confidence=confidence,
            reasoning=f'Detected {threat_type} pattern',
            recommended_action='block_and_investigate'
        )

    def analyze_order_book(self, orders: list) -> ThreatAssessment:
        """Analyze order book for manipulation patterns."""
        if not orders:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                threat_type='none',
                confidence=0.95,
                reasoning='No orders to analyze',
                recommended_action='allow'
            )

        threats = []

        # Check quote stuffing: >50 orders in 1 second window
        timestamps = []
        for order in orders:
            ts = order.get('timestamp', datetime.now())
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            timestamps.append(ts)

        if len(timestamps) >= 2:
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            if time_span <= 1.0 and len(orders) > 50:
                threats.append(('quote_stuffing', 0.90, 'HIGH'))

        # Check spoofing: large orders cancelled quickly, compared to other orders' average
        if orders:
            amounts = [o.get('amount', 0) for o in orders]
            # Use median of all amounts or average excluding max as baseline
            sorted_amounts = sorted(amounts)
            if len(sorted_amounts) > 1:
                baseline_amounts = sorted_amounts[:-1]  # Exclude the largest
                avg_baseline = sum(baseline_amounts) / len(baseline_amounts)
            else:
                avg_baseline = sorted_amounts[0]

            for order in orders:
                cancelled_secs = order.get('cancelled_within_seconds')
                if avg_baseline > 0 and order.get('amount', 0) > 10 * avg_baseline and cancelled_secs is not None and cancelled_secs <= 5:
                    threats.append(('spoofing', 0.85, 'HIGH'))
                    break

        # Check layering: multiple large orders at different price levels cancelled quickly
        total_amount = sum(o.get('amount', 0) for o in orders)
        avg_order_amount = total_amount / max(len(orders), 1)
        cancelled_large = [o for o in orders if o.get('cancelled') and o.get('amount', 0) > 5 * avg_order_amount]
        if len(cancelled_large) >= 3:
            threats.append(('layering', 0.80, 'MEDIUM'))

        # Check front-running: order placed before large pending orders for same asset
        if orders:
            amounts = [o.get('amount', 0) for o in orders]
            avg_amount = sum(amounts) / len(amounts) if amounts else 1
            for i, order in enumerate(orders):
                later_large = [o for o in orders[i+1:]
                               if o.get('asset') == order.get('asset')
                               and o.get('amount', 0) > 10 * avg_amount]
                if later_large and order.get('side') == later_large[0].get('side'):
                    threats.append(('front_running', 0.75, 'MEDIUM'))
                    break

        if not threats:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                threat_type='none',
                confidence=0.95,
                reasoning='No suspicious order patterns detected',
                recommended_action='allow'
            )

        threat_type, confidence, level = threats[0]
        return ThreatAssessment(
            threat_level=ThreatLevel[level],
            threat_type=threat_type,
            confidence=confidence,
            reasoning=f'Detected {threat_type} in order book',
            recommended_action='flag_for_review'
        )
