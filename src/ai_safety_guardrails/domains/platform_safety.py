from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import statistics
import collections

from ai_safety_guardrails.core.threat_level import ThreatLevel


@dataclass
class ContentAssessment:
    is_safe: bool
    threat_level: ThreatLevel
    threat_types: List[str]
    confidence: float
    reasoning: str
    recommended_action: str


@dataclass
class CoordinationAssessment:
    is_coordinated: bool
    threat_level: ThreatLevel
    coordination_type: str
    confidence: float
    affected_accounts: List[str]
    reasoning: str
    recommended_action: str


class PlatformSafetyGuard:
    """Guard for detecting platform safety violations."""

    def analyze_content(self, content: dict) -> ContentAssessment:
        """Analyze content for safety violations."""
        threats = []

        # Misinformation
        if content.get('contains_false_claims') or content.get('fact_check_failed'):
            threats.append('misinformation')

        # Harassment
        if content.get('targeted_at') and (content.get('contains_threats') or content.get('contains_slurs')):
            threats.append('harassment')

        # Deepfakes
        if content.get('metadata_inconsistent') or content.get('ai_generated_detected'):
            threats.append('deepfake')

        # Coordinated spreading
        if content.get('coordinated_spread'):
            threats.append('coordinated_inauthentic_behavior')

        if not threats:
            return ContentAssessment(
                is_safe=True,
                threat_level=ThreatLevel.LOW,
                threat_types=[],
                confidence=0.95,
                reasoning='Content appears safe',
                recommended_action='allow'
            )

        level = ThreatLevel.CRITICAL if len(threats) > 2 else (ThreatLevel.HIGH if len(threats) > 1 else ThreatLevel.MEDIUM)
        return ContentAssessment(
            is_safe=False,
            threat_level=level,
            threat_types=threats,
            confidence=0.85,
            reasoning=f'Detected {len(threats)} threat(s): {", ".join(threats)}',
            recommended_action='remove_and_report'
        )

    def detect_coordinated_behavior(self, accounts: list, actions: list) -> CoordinationAssessment:
        """Detect coordinated inauthentic behavior."""
        if not accounts or not actions:
            return CoordinationAssessment(
                is_coordinated=False,
                threat_level=ThreatLevel.LOW,
                coordination_type='none',
                confidence=0.95,
                affected_accounts=[],
                reasoning='Insufficient data',
                recommended_action='monitor'
            )

        # Check if many accounts target same content
        targets = [a.get('target_id') for a in actions if a.get('target_id')]
        target_counts = collections.Counter(targets)

        if target_counts and max(target_counts.values()) > len(accounts) * 0.7:
            most_targeted = max(target_counts, key=target_counts.get)
            affected = [a.get('account_id') for a in actions if a.get('target_id') == most_targeted]
            return CoordinationAssessment(
                is_coordinated=True,
                threat_level=ThreatLevel.HIGH,
                coordination_type='coordinated_targeting',
                confidence=0.85,
                affected_accounts=affected,
                reasoning=f'{max(target_counts.values())} accounts targeting same content',
                recommended_action='investigate_network'
            )

        # Check account age similarity (bot farms)
        creation_dates = [a.get('account_created') for a in accounts if a.get('account_created')]
        if len(creation_dates) > 2:
            numeric_dates = []
            for d in creation_dates:
                if isinstance(d, datetime):
                    numeric_dates.append(d.timestamp())
                elif isinstance(d, (int, float)):
                    numeric_dates.append(float(d))

            if numeric_dates and len(numeric_dates) >= 2:
                date_range = max(numeric_dates) - min(numeric_dates)
                if date_range < 86400:  # All created within 24 hours
                    return CoordinationAssessment(
                        is_coordinated=True,
                        threat_level=ThreatLevel.HIGH,
                        coordination_type='bot_farm',
                        confidence=0.80,
                        affected_accounts=[a.get('account_id') for a in accounts],
                        reasoning='Multiple accounts created within 24 hours',
                        recommended_action='suspend_accounts'
                    )

        return CoordinationAssessment(
            is_coordinated=False,
            threat_level=ThreatLevel.LOW,
            coordination_type='none',
            confidence=0.90,
            affected_accounts=[],
            reasoning='No coordinated behavior detected',
            recommended_action='allow'
        )
