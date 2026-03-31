from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import statistics

from ai_safety_guardrails.core.threat_level import ThreatLevel


@dataclass
class ClaimAssessment:
    is_suspicious: bool
    threat_level: ThreatLevel
    fraud_indicators: List[str]
    confidence: float
    reasoning: str
    recommended_action: str


@dataclass
class PatternAssessment:
    is_suspicious: bool
    threat_level: ThreatLevel
    pattern_type: str
    confidence: float
    reasoning: str
    recommended_action: str


class HealthcareIntegrityMonitor:
    """Monitor for detecting healthcare integrity violations."""

    def __init__(self):
        self._treatment_history: Dict[str, List[Dict]] = {}

    def analyze_claim(self, claim: dict) -> ClaimAssessment:
        """Analyze a healthcare claim for fraud indicators."""
        indicators = []

        # False claims: impossible combinations
        if claim.get('impossible_combination'):
            indicators.append('impossible_procedure_combination')

        # Upcoding: billing for more expensive procedure than performed
        billed_code = claim.get('billed_procedure_code', '')
        actual_code = claim.get('actual_procedure_code', '')
        if billed_code and actual_code and billed_code != actual_code:
            billed_level = int(billed_code[-1]) if billed_code and billed_code[-1].isdigit() else 0
            actual_level = int(actual_code[-1]) if actual_code and actual_code[-1].isdigit() else 0
            if billed_level > actual_level:
                indicators.append('upcoding: billed procedure more expensive than actual')

        # Ghost services: billing for services not rendered
        if claim.get('service_not_rendered'):
            indicators.append('ghost_service: billing for unrendered service')

        # Duplicate billing
        if claim.get('is_duplicate'):
            indicators.append('duplicate_billing')

        if not indicators:
            return ClaimAssessment(
                is_suspicious=False,
                threat_level=ThreatLevel.LOW,
                fraud_indicators=[],
                confidence=0.95,
                reasoning='No fraud indicators detected',
                recommended_action='approve'
            )

        level = ThreatLevel.HIGH if len(indicators) > 1 else ThreatLevel.MEDIUM
        return ClaimAssessment(
            is_suspicious=True,
            threat_level=level,
            fraud_indicators=indicators,
            confidence=0.85,
            reasoning=f'Detected {len(indicators)} fraud indicator(s)',
            recommended_action='reject_and_investigate'
        )

    def analyze_treatment_pattern(self, patient_id: str, treatments: list) -> PatternAssessment:
        """Analyze treatment patterns for exploitation."""
        if not treatments:
            return PatternAssessment(
                is_suspicious=False,
                threat_level=ThreatLevel.LOW,
                pattern_type='none',
                confidence=0.95,
                reasoning='No treatments to analyze',
                recommended_action='allow'
            )

        # Unauthorized data access pattern: many record accesses (check first)
        access_count = sum(1 for t in treatments if t.get('type') == 'data_access')
        if access_count > 20:
            return PatternAssessment(
                is_suspicious=True,
                threat_level=ThreatLevel.HIGH,
                pattern_type='data_breach',
                confidence=0.80,
                reasoning=f'Excessive data access: {access_count} accesses',
                recommended_action='block_and_investigate'
            )

        # Unnecessary treatment: same procedure repeated many times
        procedure_counts: Dict[str, int] = {}
        for treatment in treatments:
            proc = treatment.get('procedure', '')
            procedure_counts[proc] = procedure_counts.get(proc, 0) + 1

        max_repeat = max(procedure_counts.values()) if procedure_counts else 0
        if max_repeat > 10:
            most_repeated = max(procedure_counts, key=procedure_counts.get)
            return PatternAssessment(
                is_suspicious=True,
                threat_level=ThreatLevel.HIGH,
                pattern_type='unnecessary_treatment',
                confidence=0.85,
                reasoning=f'Procedure "{most_repeated}" repeated {max_repeat} times',
                recommended_action='investigate'
            )

        return PatternAssessment(
            is_suspicious=False,
            threat_level=ThreatLevel.LOW,
            pattern_type='none',
            confidence=0.95,
            reasoning='Normal treatment pattern',
            recommended_action='allow'
        )
