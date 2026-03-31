import pytest
from ai_safety_guardrails.core.ethical_framework import (
    EthicsClassifier, EthicsResult, StakeholderImpactAssessor, IntentOutcomeAnalyzer, Domain, Severity
)


def test_ethics_classifier_ethical_action():
    classifier = EthicsClassifier()
    action = {
        'domain': 'FINANCIAL',
        'action_type': 'standard_trade',
        'amount': 1000,
        'transparent': True
    }
    result = classifier.classify(action)
    assert isinstance(result, EthicsResult)
    assert result.is_ethical == True
    assert result.confidence > 0


def test_ethics_classifier_unethical_action():
    classifier = EthicsClassifier()
    action = {
        'domain': 'FINANCIAL',
        'action_type': 'insider_trading',
        'contains_fraud': True,
        'deceptive': True
    }
    result = classifier.classify(action)
    assert isinstance(result, EthicsResult)
    assert result.is_ethical == False
    assert len(result.violations) > 0


def test_ethics_result_fields():
    result = EthicsResult(
        is_ethical=True,
        confidence=0.9,
        violations=[],
        domain='FINANCIAL',
        severity='LOW',
        reasoning='Test reasoning'
    )
    assert result.is_ethical == True
    assert result.confidence == 0.9
    assert result.domain == 'FINANCIAL'


def test_stakeholder_impact_assessor():
    assessor = StakeholderImpactAssessor()
    action = {'action_type': 'price_fix', 'domain': 'BUSINESS', 'affected_parties': ['consumers', 'competitors']}
    result = assessor.assess(action)
    assert isinstance(result, dict)
    assert 'stakeholders' in result or len(result) > 0


def test_intent_outcome_analyzer():
    analyzer = IntentOutcomeAnalyzer()
    action = {'intent': 'profit', 'expected_outcome': 'gain', 'actual_outcome': 'harm'}
    result = analyzer.analyze(action)
    assert isinstance(result, dict)


def test_domain_enum():
    assert Domain.FINANCIAL.value == 'FINANCIAL'
    assert Domain.GAMING.value == 'GAMING'
    assert Domain.HEALTHCARE.value == 'HEALTHCARE'


def test_severity_enum():
    assert Severity.LOW.value == 'LOW'
    assert Severity.CRITICAL.value == 'CRITICAL'
