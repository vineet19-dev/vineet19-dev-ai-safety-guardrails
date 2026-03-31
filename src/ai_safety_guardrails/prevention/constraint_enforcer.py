from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


@dataclass
class Constraint:
    name: str
    domain: str
    constraint_type: str  # rate_limit, amount_limit, behavioral
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ''


@dataclass
class EnforcementResult:
    is_compliant: bool
    violated_constraints: List[str]
    enforcement_action: str
    reasoning: str


class ConstraintEnforcer:
    """Domain-specific constraint enforcement."""

    def __init__(self):
        self._constraints: Dict[str, List[Constraint]] = {}
        self._action_counts: Dict[str, int] = {}

    def add_constraint(self, domain: str, constraint: Constraint) -> None:
        """Add a constraint for a domain."""
        if domain not in self._constraints:
            self._constraints[domain] = []
        self._constraints[domain].append(constraint)

    def enforce(self, action: dict) -> EnforcementResult:
        """Enforce all applicable constraints on an action."""
        domain = action.get('domain', 'general')
        violated = []

        constraints = self._constraints.get(domain, []) + self._constraints.get('general', [])

        for constraint in constraints:
            if constraint.constraint_type == 'amount_limit':
                max_amount = constraint.parameters.get('max_amount', float('inf'))
                if action.get('amount', 0) > max_amount:
                    violated.append(f'{constraint.name}: amount {action.get("amount")} exceeds limit {max_amount}')

            elif constraint.constraint_type == 'rate_limit':
                max_rate = constraint.parameters.get('max_per_minute', float('inf'))
                action_key = f'{domain}_{action.get("action_type", "")}'
                current_count = self._action_counts.get(action_key, 0) + 1
                self._action_counts[action_key] = current_count
                if current_count > max_rate:
                    violated.append(f'{constraint.name}: rate limit exceeded ({current_count} > {max_rate})')

            elif constraint.constraint_type == 'behavioral':
                forbidden_actions = constraint.parameters.get('forbidden_actions', [])
                if action.get('action_type') in forbidden_actions:
                    violated.append(f'{constraint.name}: forbidden action type {action.get("action_type")}')

        if not violated:
            return EnforcementResult(
                is_compliant=True,
                violated_constraints=[],
                enforcement_action='allow',
                reasoning='All constraints satisfied'
            )

        return EnforcementResult(
            is_compliant=False,
            violated_constraints=violated,
            enforcement_action='block',
            reasoning=f'Violated {len(violated)} constraint(s)'
        )
