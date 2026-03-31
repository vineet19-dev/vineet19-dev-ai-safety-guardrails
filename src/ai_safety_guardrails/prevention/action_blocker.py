from dataclasses import dataclass
from typing import Optional, Any
from enum import Enum


class FrictionLevel(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class BlockDecision:
    should_block: bool
    reason: str
    alternative_suggestion: Optional[str]
    escalate_to_human: bool
    friction_level: FrictionLevel


class ActionBlocker:
    """Real-time action blocking with reasoning and escalation."""

    def evaluate_and_block(self, action: dict, threat: Any) -> BlockDecision:
        """Evaluate whether to block an action based on threat assessment."""
        threat_level = getattr(threat, 'threat_level', None)

        if threat_level is None:
            level_str = str(threat).upper() if threat else 'LOW'
        else:
            level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level).upper()

        if level_str == 'CRITICAL':
            return BlockDecision(
                should_block=True,
                reason=f'Critical threat detected: {getattr(threat, "threat_type", "unknown")}',
                alternative_suggestion=None,
                escalate_to_human=True,
                friction_level=FrictionLevel.HIGH
            )
        elif level_str == 'HIGH':
            return BlockDecision(
                should_block=True,
                reason=f'High threat detected: {getattr(threat, "threat_type", "unknown")}',
                alternative_suggestion=self._suggest_alternative(action, threat),
                escalate_to_human=True,
                friction_level=FrictionLevel.HIGH
            )
        elif level_str == 'MEDIUM':
            return BlockDecision(
                should_block=False,
                reason=f'Medium threat detected: {getattr(threat, "threat_type", "unknown")}',
                alternative_suggestion=self._suggest_alternative(action, threat),
                escalate_to_human=False,
                friction_level=FrictionLevel.MEDIUM
            )
        else:
            return BlockDecision(
                should_block=False,
                reason='No significant threat detected',
                alternative_suggestion=None,
                escalate_to_human=False,
                friction_level=FrictionLevel.NONE
            )

    def _suggest_alternative(self, action: dict, threat: Any) -> str:
        """Suggest an alternative action."""
        threat_type = getattr(threat, 'threat_type', 'unknown')

        suggestions = {
            'wash_trading': 'Consider trading with unrelated counterparties',
            'spoofing': 'Place genuine orders with intent to execute',
            'botting': 'Ensure actions are performed by a human player',
            'collusion': 'Engage in fair, independent competition',
            'fraud': 'Ensure all representations are accurate',
            'bribery': 'Use official channels for all payments',
        }

        return suggestions.get(threat_type, 'Review and modify the action to comply with regulations')
