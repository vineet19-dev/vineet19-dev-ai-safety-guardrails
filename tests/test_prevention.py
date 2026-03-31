import pytest
from ai_safety_guardrails.prevention.action_blocker import ActionBlocker, BlockDecision, FrictionLevel
from ai_safety_guardrails.prevention.constraint_enforcer import ConstraintEnforcer, Constraint, EnforcementResult
from ai_safety_guardrails.core.threat_level import ThreatLevel
from dataclasses import dataclass


@dataclass
class MockThreat:
    threat_level: ThreatLevel
    threat_type: str


class TestActionBlocker:
    def setup_method(self):
        self.blocker = ActionBlocker()

    def _make_threat(self, level, threat_type='test_threat'):
        return MockThreat(threat_level=ThreatLevel[level], threat_type=threat_type)

    def test_block_critical_threat(self):
        threat = self._make_threat('CRITICAL', 'wash_trading')
        action = {'action_type': 'trade', 'amount': 1000}
        result = self.blocker.evaluate_and_block(action, threat)
        assert isinstance(result, BlockDecision)
        assert result.should_block == True
        assert result.escalate_to_human == True
        assert result.friction_level == FrictionLevel.HIGH

    def test_block_high_threat(self):
        threat = self._make_threat('HIGH', 'spoofing')
        action = {'action_type': 'order', 'amount': 5000}
        result = self.blocker.evaluate_and_block(action, threat)
        assert result.should_block == True
        assert result.escalate_to_human == True

    def test_no_block_medium_threat(self):
        threat = self._make_threat('MEDIUM', 'suspicious_pattern')
        action = {'action_type': 'trade', 'amount': 100}
        result = self.blocker.evaluate_and_block(action, threat)
        assert result.should_block == False
        assert result.friction_level in (FrictionLevel.MEDIUM, FrictionLevel.LOW)

    def test_no_block_low_threat(self):
        threat = self._make_threat('LOW', 'none')
        action = {'action_type': 'trade', 'amount': 100}
        result = self.blocker.evaluate_and_block(action, threat)
        assert result.should_block == False
        assert result.escalate_to_human == False
        assert result.friction_level == FrictionLevel.NONE

    def test_alternative_suggestion_provided(self):
        threat = self._make_threat('HIGH', 'wash_trading')
        action = {'action_type': 'trade'}
        result = self.blocker.evaluate_and_block(action, threat)
        assert result.alternative_suggestion is not None
        assert len(result.alternative_suggestion) > 0


class TestConstraintEnforcer:
    def setup_method(self):
        self.enforcer = ConstraintEnforcer()

    def test_add_and_enforce_amount_constraint(self):
        constraint = Constraint(
            name='max_trade_amount',
            domain='financial',
            constraint_type='amount_limit',
            parameters={'max_amount': 10000},
            description='Maximum trade amount'
        )
        self.enforcer.add_constraint('financial', constraint)

        # Action within limit
        action = {'domain': 'financial', 'action_type': 'trade', 'amount': 5000}
        result = self.enforcer.enforce(action)
        assert result.is_compliant == True

        # Action exceeding limit
        action2 = {'domain': 'financial', 'action_type': 'trade', 'amount': 15000}
        result2 = self.enforcer.enforce(action2)
        assert result2.is_compliant == False
        assert len(result2.violated_constraints) > 0

    def test_behavioral_constraint(self):
        constraint = Constraint(
            name='no_spam',
            domain='social',
            constraint_type='behavioral',
            parameters={'forbidden_actions': ['mass_message', 'spam_post']},
            description='Prevent spam behavior'
        )
        self.enforcer.add_constraint('social', constraint)

        action = {'domain': 'social', 'action_type': 'mass_message'}
        result = self.enforcer.enforce(action)
        assert result.is_compliant == False

    def test_no_constraints(self):
        enforcer = ConstraintEnforcer()
        action = {'domain': 'unknown', 'action_type': 'do_something', 'amount': 999999}
        result = enforcer.enforce(action)
        assert result.is_compliant == True

    def test_enforcement_result_fields(self):
        result = EnforcementResult(
            is_compliant=True,
            violated_constraints=[],
            enforcement_action='allow',
            reasoning='All good'
        )
        assert result.is_compliant == True
        assert result.enforcement_action == 'allow'
