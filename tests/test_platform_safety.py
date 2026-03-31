import pytest
from datetime import datetime, timedelta
from ai_safety_guardrails.domains.platform_safety import PlatformSafetyGuard, ContentAssessment, CoordinationAssessment, ThreatLevel


def test_safe_content():
    guard = PlatformSafetyGuard()
    content = {
        'content_id': 'c1',
        'text': 'Hello world',
        'contains_false_claims': False,
        'fact_check_failed': False
    }
    result = guard.analyze_content(content)
    assert isinstance(result, ContentAssessment)
    assert result.is_safe == True
    assert result.threat_level == ThreatLevel.LOW


def test_misinformation_detection():
    guard = PlatformSafetyGuard()
    content = {
        'content_id': 'c2',
        'text': 'False health claim',
        'contains_false_claims': True,
        'fact_check_failed': True
    }
    result = guard.analyze_content(content)
    assert result.is_safe == False
    assert 'misinformation' in result.threat_types


def test_harassment_detection():
    guard = PlatformSafetyGuard()
    content = {
        'content_id': 'c3',
        'targeted_at': 'user123',
        'contains_threats': True,
        'contains_slurs': False
    }
    result = guard.analyze_content(content)
    assert result.is_safe == False
    assert 'harassment' in result.threat_types


def test_deepfake_detection():
    guard = PlatformSafetyGuard()
    content = {
        'content_id': 'c4',
        'media_type': 'video',
        'metadata_inconsistent': True,
        'ai_generated_detected': True
    }
    result = guard.analyze_content(content)
    assert result.is_safe == False
    assert 'deepfake' in result.threat_types


def test_coordinated_behavior_detection():
    guard = PlatformSafetyGuard()
    now = datetime.now()
    accounts = [{'account_id': f'acc{i}'} for i in range(10)]
    # Many accounts targeting same content
    actions = [{'account_id': f'acc{i}', 'action_type': 'share', 'target_id': 'viral_post_123'} for i in range(8)]
    actions += [{'account_id': 'acc8', 'action_type': 'like', 'target_id': 'other_post'}]
    actions += [{'account_id': 'acc9', 'action_type': 'comment', 'target_id': 'other_post_2'}]

    result = guard.detect_coordinated_behavior(accounts, actions)
    assert isinstance(result, CoordinationAssessment)
    assert result.is_coordinated == True
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.CRITICAL)


def test_no_coordination():
    guard = PlatformSafetyGuard()
    accounts = [{'account_id': f'acc{i}'} for i in range(5)]
    actions = [
        {'account_id': 'acc0', 'action_type': 'share', 'target_id': 'post_1'},
        {'account_id': 'acc1', 'action_type': 'like', 'target_id': 'post_2'},
        {'account_id': 'acc2', 'action_type': 'comment', 'target_id': 'post_3'},
    ]
    result = guard.detect_coordinated_behavior(accounts, actions)
    assert isinstance(result, CoordinationAssessment)
