"""
Financial Trading Monitor
=========================
Detects front-running, market manipulation, spoofing, layering,
pump-and-dump, quote stuffing, wash trading, insider trading, and
price fixing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ethical_framework import Action, Domain, Severity


@dataclass
class TradingViolation:
    rule: str
    severity: Severity
    details: str
    regulatory_reference: str = ""


@dataclass
class TradingAnalysis:
    action_id: str
    violations: list[TradingViolation] = field(default_factory=list)
    risk_score: float = 0.0
    compliant: bool = True
    summary: str = ""

    def add(self, violation: TradingViolation) -> None:
        self.violations.append(violation)
        self.compliant = False


_SEVERITY_WEIGHT = {
    Severity.LOW: 0.1,
    Severity.MEDIUM: 0.3,
    Severity.HIGH: 0.6,
    Severity.CRITICAL: 1.0,
}


class FinancialTradingMonitor:
    """
    Domain-specific detector for financial trading violations.

    Expected action parameters (all optional but used when present):
      - order_type       : "market" | "limit" | "cancel"
      - price            : float
      - quantity         : int / float
      - side             : "buy" | "sell"
      - time_to_live_ms  : int  (cancel latency for spoofing detection)
      - cancel_ratio     : float (0-1, fraction of orders cancelled)
      - order_rate_per_sec: float
      - is_wash_trade    : bool
      - uses_non_public_info: bool
      - involves_price_agreement: bool  (for price-fixing detection)
    """

    # Thresholds
    _CANCEL_RATIO_SPOOFING = 0.85      # 85 %+ cancellation = spoofing signal
    _QUOTE_STUFF_RATE = 500            # orders/sec
    _WASH_THRESHOLD = True
    _TTL_SPOOFING_MS = 500             # orders cancelled within 500 ms

    def analyze(self, action: Action) -> TradingAnalysis:
        if action.domain != Domain.FINANCIAL_TRADING:
            return TradingAnalysis(action_id=action.action_id, summary="N/A – wrong domain")

        result = TradingAnalysis(action_id=action.action_id)
        p = action.parameters

        self._check_front_running(result, p, action.context)
        self._check_spoofing_layering(result, p)
        self._check_pump_and_dump(result, p, action.context)
        self._check_quote_stuffing(result, p)
        self._check_wash_trading(result, p)
        self._check_insider_trading(result, p)
        self._check_price_fixing(result, p)

        weights = [_SEVERITY_WEIGHT[v.severity] for v in result.violations]
        result.risk_score = round(min(1.0, sum(weights)), 3)
        result.summary = self._build_summary(result)
        return result

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_front_running(
        self, result: TradingAnalysis, p: dict[str, Any], ctx: dict[str, Any]
    ) -> None:
        # Front-running: placing an order ahead of a known pending large order
        if p.get("front_run") or ctx.get("pending_client_order_ahead"):
            result.add(
                TradingViolation(
                    rule="front_running",
                    severity=Severity.CRITICAL,
                    details="Order placed in advance of a known pending client order.",
                    regulatory_reference="SEC Rule 10b-5; FINRA Rule 5270",
                )
            )

    def _check_spoofing_layering(
        self, result: TradingAnalysis, p: dict[str, Any]
    ) -> None:
        cancel_ratio = float(p.get("cancel_ratio", 0))
        ttl_ms = p.get("time_to_live_ms")

        if cancel_ratio >= self._CANCEL_RATIO_SPOOFING:
            result.add(
                TradingViolation(
                    rule="spoofing",
                    severity=Severity.HIGH,
                    details=(
                        f"Cancel ratio {cancel_ratio:.0%} exceeds spoofing threshold "
                        f"({self._CANCEL_RATIO_SPOOFING:.0%})."
                    ),
                    regulatory_reference="Dodd-Frank Act §747; CFTC Anti-Spoofing Rule",
                )
            )

        if ttl_ms is not None and int(ttl_ms) < self._TTL_SPOOFING_MS:
            result.add(
                TradingViolation(
                    rule="layering",
                    severity=Severity.HIGH,
                    details=(
                        f"Order cancelled within {ttl_ms} ms – consistent with layering."
                    ),
                    regulatory_reference="FINRA Rule 5210",
                )
            )

    def _check_pump_and_dump(
        self, result: TradingAnalysis, p: dict[str, Any], ctx: dict[str, Any]
    ) -> None:
        if p.get("pump_and_dump") or ctx.get("coordinated_price_inflation"):
            result.add(
                TradingViolation(
                    rule="pump_and_dump",
                    severity=Severity.CRITICAL,
                    details="Coordinated artificial price inflation detected.",
                    regulatory_reference="Securities Exchange Act §9(a)(2)",
                )
            )

    def _check_quote_stuffing(
        self, result: TradingAnalysis, p: dict[str, Any]
    ) -> None:
        rate = float(p.get("order_rate_per_sec", 0))
        if rate >= self._QUOTE_STUFF_RATE:
            result.add(
                TradingViolation(
                    rule="quote_stuffing",
                    severity=Severity.HIGH,
                    details=(
                        f"Order submission rate {rate}/s exceeds quote-stuffing "
                        f"threshold ({self._QUOTE_STUFF_RATE}/s)."
                    ),
                    regulatory_reference="SEC Market Access Rule 15c3-5",
                )
            )

    def _check_wash_trading(
        self, result: TradingAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("is_wash_trade"):
            result.add(
                TradingViolation(
                    rule="wash_trading",
                    severity=Severity.HIGH,
                    details="Wash trade detected: buy and sell on same instrument by same beneficial owner.",
                    regulatory_reference="Commodity Exchange Act §4c(a)",
                )
            )

    def _check_insider_trading(
        self, result: TradingAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("uses_non_public_info"):
            result.add(
                TradingViolation(
                    rule="insider_trading",
                    severity=Severity.CRITICAL,
                    details="Trade based on material non-public information.",
                    regulatory_reference="SEC Rule 10b-5; Insider Trading Sanctions Act",
                )
            )

    def _check_price_fixing(
        self, result: TradingAnalysis, p: dict[str, Any]
    ) -> None:
        if p.get("involves_price_agreement"):
            result.add(
                TradingViolation(
                    rule="price_fixing",
                    severity=Severity.CRITICAL,
                    details="Coordinated price agreement with other market participants.",
                    regulatory_reference="Sherman Antitrust Act §1",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_summary(self, result: TradingAnalysis) -> str:
        if result.compliant:
            return f"Action {result.action_id}: compliant – no trading violations detected."
        names = [v.rule for v in result.violations]
        return (
            f"Action {result.action_id}: NON-COMPLIANT – "
            f"{len(names)} violation(s): {', '.join(names)}. "
            f"Risk score: {result.risk_score:.2f}."
        )
