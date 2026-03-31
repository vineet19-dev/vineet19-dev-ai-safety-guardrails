"""Unified ethical framework for AI safety guardrails."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod


class Domain(Enum):
    FINANCIAL = "FINANCIAL"
    GAMING = "GAMING"
    BUSINESS = "BUSINESS"
    HEALTHCARE = "HEALTHCARE"
    SOCIAL = "SOCIAL"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EthicsResult:
    is_ethical: bool
    confidence: float
    violations: List[str]
    domain: str
    severity: str
    reasoning: str


class DomainRuleEngine(ABC):
    """Base class for domain-specific rule engines."""

    @abstractmethod
    def evaluate(self, action: dict) -> List[str]:
        """Evaluate an action and return list of violations."""
        pass


class FinancialRuleEngine(DomainRuleEngine):
    def evaluate(self, action: dict) -> List[str]:
        violations = []
        if action.get('contains_fraud') or action.get('insider_info'):
            violations.append('financial_fraud')
        if action.get('wash_trade') or action.get('action_type') == 'wash_trading':
            violations.append('wash_trading')
        if action.get('deceptive'):
            violations.append('deceptive_practice')
        return violations


class BusinessRuleEngine(DomainRuleEngine):
    def evaluate(self, action: dict) -> List[str]:
        violations = []
        if action.get('contains_fraud') or action.get('misrepresentation'):
            violations.append('business_fraud')
        if action.get('price_coordination'):
            violations.append('anti_competitive')
        if action.get('deceptive'):
            violations.append('deceptive_practice')
        return violations


class GamingRuleEngine(DomainRuleEngine):
    def evaluate(self, action: dict) -> List[str]:
        violations = []
        if action.get('bot_assisted'):
            violations.append('botting')
        if action.get('collusion'):
            violations.append('collusion')
        return violations


class HealthcareRuleEngine(DomainRuleEngine):
    def evaluate(self, action: dict) -> List[str]:
        violations = []
        if action.get('false_claim') or action.get('upcoding'):
            violations.append('healthcare_fraud')
        if action.get('unauthorized_access'):
            violations.append('data_breach')
        return violations


class SocialRuleEngine(DomainRuleEngine):
    def evaluate(self, action: dict) -> List[str]:
        violations = []
        if action.get('misinformation') or action.get('contains_false_claims'):
            violations.append('misinformation')
        if action.get('harassment'):
            violations.append('harassment')
        return violations


class EthicsClassifier:
    """Unified ethics classifier supporting multiple domains."""

    def __init__(self):
        self._rule_engines = {
            Domain.FINANCIAL: FinancialRuleEngine(),
            Domain.BUSINESS: BusinessRuleEngine(),
            Domain.GAMING: GamingRuleEngine(),
            Domain.HEALTHCARE: HealthcareRuleEngine(),
            Domain.SOCIAL: SocialRuleEngine(),
        }

    def classify(self, action: dict) -> EthicsResult:
        """Classify an action as ethical or unethical."""
        domain_str = action.get('domain', 'FINANCIAL').upper()
        try:
            domain = Domain[domain_str]
        except KeyError:
            domain = Domain.FINANCIAL

        engine = self._rule_engines.get(domain)
        violations = engine.evaluate(action) if engine else []

        # General ethical checks across domains
        if action.get('deceptive') or action.get('contains_fraud'):
            violations.append('general_deception')

        # Deduplicate
        violations = list(set(violations))

        is_ethical = len(violations) == 0
        confidence = 0.90 if violations else 0.95
        severity = 'LOW' if is_ethical else ('HIGH' if len(violations) > 1 else 'MEDIUM')

        return EthicsResult(
            is_ethical=is_ethical,
            confidence=confidence,
            violations=violations,
            domain=domain.value,
            severity=severity,
            reasoning='Violations found: ' + ', '.join(violations) if violations else 'No violations detected'
        )


class StakeholderImpactAssessor:
    """Assesses the impact of actions on various stakeholders."""

    def assess(self, action: dict) -> dict:
        """Assess stakeholder impact of an action."""
        affected_parties = action.get('affected_parties', [])
        action_type = action.get('action_type', 'unknown')

        impact_level = 'low'
        if action.get('contains_fraud') or action.get('deceptive'):
            impact_level = 'high'
        elif action.get('price_coordination') or action.get('market_manipulation'):
            impact_level = 'medium'

        stakeholders = {}

        domain = action.get('domain', 'GENERAL')
        if domain == 'FINANCIAL':
            stakeholders = {
                'investors': impact_level,
                'market': impact_level,
                'regulators': 'medium' if impact_level == 'high' else 'low'
            }
        elif domain == 'BUSINESS':
            stakeholders = {
                'consumers': impact_level,
                'competitors': 'medium',
                'employees': 'low'
            }
        else:
            stakeholders = {'general_public': impact_level}

        for party in affected_parties:
            if party not in stakeholders:
                stakeholders[party] = impact_level

        return {
            'stakeholders': stakeholders,
            'overall_impact': impact_level,
            'action_type': action_type
        }


class IntentOutcomeAnalyzer:
    """Analyzes the alignment between intent and outcome."""

    def analyze(self, action: dict) -> dict:
        """Analyze intent vs outcome alignment."""
        intent = action.get('intent', 'unknown')
        expected_outcome = action.get('expected_outcome', 'unknown')
        actual_outcome = action.get('actual_outcome', 'unknown')

        aligned = (expected_outcome == actual_outcome)

        harmful_intents = ['harm', 'deceive', 'manipulate', 'exploit', 'defraud']
        intent_harmful = any(h in str(intent).lower() for h in harmful_intents)

        harmful_outcomes = ['harm', 'loss', 'damage', 'violation']
        outcome_harmful = any(h in str(actual_outcome).lower() for h in harmful_outcomes)

        alignment_score = 1.0 if aligned else 0.5
        ethics_score = 0.0 if (intent_harmful or outcome_harmful) else 1.0

        return {
            'intent': intent,
            'expected_outcome': expected_outcome,
            'actual_outcome': actual_outcome,
            'aligned': aligned,
            'alignment_score': alignment_score,
            'intent_harmful': intent_harmful,
            'outcome_harmful': outcome_harmful,
            'ethics_score': ethics_score
        }
