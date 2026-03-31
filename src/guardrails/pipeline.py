"""
Safety Pipeline
===============
Main entry point that orchestrates the ethical framework, behaviour
monitoring, domain-specific detectors, prevention engine, and audit logger
into a single coherent pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TextIO

from .audit_logger import AuditEntry, AuditLogger
from .behavior_monitor import BehaviorMonitor, BehaviorRecord
from .detectors.business_ethics import BusinessAnalysis, BusinessEthicsValidator
from .detectors.financial_trading import FinancialTradingMonitor, TradingAnalysis
from .detectors.gaming import GamingAnalysis, GamingBehaviorAnalyzer
from .detectors.healthcare import HealthcareAnalysis, HealthcareIntegrityMonitor
from .detectors.platform_safety import PlatformAnalysis, PlatformSafetyGuard
from .ethical_framework import Action, Domain, EthicsClassifier, EthicsVerdict
from .prevention import PreventionEngine, PreventionOutcome


@dataclass
class PipelineResult:
    """Complete result returned by SafetyPipeline.evaluate()."""

    action_id: str
    allowed: bool
    verdict: EthicsVerdict
    prevention: PreventionOutcome
    behavior: BehaviorRecord
    audit_entry: AuditEntry
    domain_analysis: (
        TradingAnalysis
        | GamingAnalysis
        | BusinessAnalysis
        | HealthcareAnalysis
        | PlatformAnalysis
        | None
    ) = None
    metadata: dict[str, Any] = field(default_factory=dict)


class SafetyPipeline:
    """
    Unified AI safety guardrails pipeline.

    Usage
    -----
    >>> pipeline = SafetyPipeline()
    >>> action = Action(
    ...     action_id="act-001",
    ...     domain=Domain.FINANCIAL_TRADING,
    ...     action_type="place_order",
    ...     parameters={"front_run": True},
    ...     actor_id="trader-99",
    ... )
    >>> result = pipeline.evaluate(action)
    >>> result.allowed
    False
    """

    def __init__(
        self,
        audit_sink: TextIO | None = None,
        escalation_callback: Any = None,
        behavior_window_seconds: float = 60.0,
        behavior_frequency_threshold: int = 20,
    ) -> None:
        self._classifier = EthicsClassifier()
        self._monitor = BehaviorMonitor(
            window_seconds=behavior_window_seconds,
            frequency_threshold=behavior_frequency_threshold,
        )
        self._prevention = PreventionEngine(escalation_callback=escalation_callback)
        self._logger = AuditLogger(sink=audit_sink)

        # Domain-specific detectors
        self._trading = FinancialTradingMonitor()
        self._gaming = GamingBehaviorAnalyzer()
        self._business = BusinessEthicsValidator()
        self._healthcare = HealthcareIntegrityMonitor()
        self._platform = PlatformSafetyGuard()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, action: Action) -> PipelineResult:
        """
        Run the full guardrails pipeline for a single action.

        1. Record behaviour and compute anomaly score.
        2. Run domain-specific detector.
        3. Run unified ethics classifier.
        4. Merge domain detector findings into ethics verdict if needed.
        5. Apply prevention measures.
        6. Log decision.
        """

        # Step 1 – Behaviour monitoring
        behavior_record = self._monitor.record(action)

        # Step 2 – Domain-specific detection
        domain_analysis = self._run_domain_detector(action)

        # Step 3 – Ethics classification
        # Enrich action parameters with domain detector findings
        enriched_action = self._enrich_with_domain_findings(action, domain_analysis)
        verdict = self._classifier.evaluate(enriched_action)

        # Step 4 – Merge domain violations into verdict if ethics missed them
        verdict = self._merge_domain_violations(verdict, domain_analysis)

        # Step 5 – Prevention
        outcome = self._prevention.process(
            action=action,
            verdict=verdict,
            anomaly_score=behavior_record.anomaly_score,
            behavior_flags=behavior_record.flags,
        )

        # Step 6 – Audit
        audit_entry = self._logger.log(
            action=action,
            verdict=verdict,
            outcome=outcome,
            anomaly_score=behavior_record.anomaly_score,
            behavior_flags=behavior_record.flags,
        )

        return PipelineResult(
            action_id=action.action_id,
            allowed=outcome.allowed,
            verdict=verdict,
            prevention=outcome,
            behavior=behavior_record,
            audit_entry=audit_entry,
            domain_analysis=domain_analysis,
        )

    def collusion_check(self, actor_a: str, actor_b: str) -> bool:
        """Return True if the two actors appear to be colluding."""
        return self._monitor.detect_collusion(actor_a, actor_b)

    def actor_summary(self, actor_id: str) -> dict[str, Any]:
        return self._monitor.get_actor_summary(actor_id)

    def compliance_report(self) -> dict[str, Any]:
        return self._logger.compliance_report()

    def transparency_report(self) -> str:
        return self._logger.transparency_report()

    def audit_entries(self) -> list[AuditEntry]:
        return self._logger.get_all_entries()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_domain_detector(
        self, action: Action
    ) -> (
        TradingAnalysis
        | GamingAnalysis
        | BusinessAnalysis
        | HealthcareAnalysis
        | PlatformAnalysis
        | None
    ):
        match action.domain:
            case Domain.FINANCIAL_TRADING:
                return self._trading.analyze(action)
            case Domain.GAMING:
                return self._gaming.analyze(action)
            case Domain.BUSINESS:
                return self._business.analyze(action)
            case Domain.HEALTHCARE:
                return self._healthcare.analyze(action)
            case Domain.SOCIAL_PLATFORM:
                return self._platform.analyze(action)
            case _:
                return None

    def _enrich_with_domain_findings(
        self,
        action: Action,
        domain_analysis: Any,
    ) -> Action:
        """
        Inject domain violation names into action parameters so the ethics
        classifier can also detect them via its regex rules.
        """
        if domain_analysis is None or getattr(domain_analysis, "compliant", True):
            return action

        # Build an enriched copy without mutating the original
        extra_params = dict(action.parameters)
        for violation in getattr(domain_analysis, "violations", []):
            extra_params[violation.rule] = True

        return Action(
            action_id=action.action_id,
            domain=action.domain,
            action_type=action.action_type,
            parameters=extra_params,
            actor_id=action.actor_id,
            context=action.context,
            metadata=action.metadata,
        )

    def _merge_domain_violations(
        self, verdict: EthicsVerdict, domain_analysis: Any
    ) -> EthicsVerdict:
        """
        Ensure domain-specific violations discovered by the specialised
        detectors are reflected in the verdict even if the ethics classifier
        did not catch them via its regex rules.
        """
        if domain_analysis is None or getattr(domain_analysis, "compliant", True):
            return verdict

        from .ethical_framework import Severity, VerdictType, _max_severity, _severity_to_verdict

        new_violations = list(verdict.violations)
        worst = verdict.severity
        for v in getattr(domain_analysis, "violations", []):
            if v.rule not in new_violations:
                new_violations.append(v.rule)
                worst = _max_severity(worst, v.severity)

        if new_violations == verdict.violations:
            return verdict

        new_verdict_type = _severity_to_verdict(worst)
        # Respect existing escalation
        if verdict.verdict == VerdictType.ESCALATE:
            new_verdict_type = VerdictType.ESCALATE

        return EthicsVerdict(
            action_id=verdict.action_id,
            verdict=new_verdict_type,
            severity=worst,
            violations=new_violations,
            stakeholder_impacts=verdict.stakeholder_impacts,
            reasoning=verdict.reasoning,
            suggested_alternatives=verdict.suggested_alternatives,
            confidence=verdict.confidence,
        )
