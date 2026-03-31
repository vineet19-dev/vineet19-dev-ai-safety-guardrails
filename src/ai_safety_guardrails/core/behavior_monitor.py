"""Behavior monitoring for AI safety guardrails."""

from datetime import datetime
from typing import List, Dict, Any
import statistics


class BehaviorMonitor:
    """Monitors agent behavior and detects anomalous patterns."""

    def __init__(self):
        self._action_history: Dict[str, List[Dict]] = {}

    def record_action(self, agent_id: str, action: dict) -> None:
        """Record an action for an agent."""
        if agent_id not in self._action_history:
            self._action_history[agent_id] = []

        entry = {**action, '_recorded_at': datetime.now().isoformat()}
        self._action_history[agent_id].append(entry)

    def get_behavior_history(self, agent_id: str) -> List[Dict]:
        """Get the behavior history for an agent."""
        return self._action_history.get(agent_id, [])

    def detect_anomalous_patterns(self, agent_id: str) -> List[Dict]:
        """Detect anomalous patterns in an agent's behavior history."""
        history = self._action_history.get(agent_id, [])
        patterns = []

        if len(history) < 3:
            return patterns

        # Check for escalating amounts
        amounts = [h.get('amount', 0) for h in history if h.get('amount')]
        if len(amounts) >= 3:
            increases = sum(1 for i in range(1, len(amounts)) if amounts[i] > amounts[i-1])
            if increases == len(amounts) - 1:
                patterns.append({
                    'type': 'escalating_amounts',
                    'description': f'Amounts monotonically increasing: {amounts}',
                    'severity': 'MEDIUM'
                })

        # Check for high-risk frequency
        high_risk_count = sum(1 for h in history if h.get('risk_level') == 'high')
        if high_risk_count > len(history) * 0.5:
            patterns.append({
                'type': 'high_risk_frequency',
                'description': f'{high_risk_count}/{len(history)} actions are high-risk',
                'severity': 'HIGH'
            })

        # Check action type diversity (low diversity = suspicious)
        action_types = [h.get('action_type', 'unknown') for h in history]
        unique_types = len(set(action_types))
        if unique_types == 1 and len(history) > 5:
            patterns.append({
                'type': 'low_action_diversity',
                'description': f'All {len(history)} actions are of the same type',
                'severity': 'LOW'
            })

        return patterns
