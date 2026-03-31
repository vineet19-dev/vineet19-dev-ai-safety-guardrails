import pytest
from datetime import datetime, timedelta
from ai_safety_guardrails.domains.gaming import GamingBehaviorAnalyzer, ThreatLevel, ThreatAssessment


def test_legitimate_player():
    analyzer = GamingBehaviorAnalyzer()
    now = datetime.now()
    # Human-like timing: 500ms-2000ms gaps
    for i in range(5):
        action = {
            'action_type': 'move',
            'location': f'zone_{i % 3}',
            'timestamp': now + timedelta(milliseconds=i * 800)
        }
        result = analyzer.analyze_player_action('player_legit', action)
    assert result.threat_level == ThreatLevel.LOW


def test_botting_detection_fast_actions():
    analyzer = GamingBehaviorAnalyzer()
    now = datetime.now()
    # Bot-like timing: 50ms gaps (way below 100ms threshold)
    for i in range(10):
        action = {
            'action_type': 'attack',
            'location': 'zone_1',
            'timestamp': now + timedelta(milliseconds=i * 50)
        }
        result = analyzer.analyze_player_action('player_bot', action)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
    assert 'bot' in result.threat_type.lower()


def test_botting_detection_regular_timing():
    analyzer = GamingBehaviorAnalyzer()
    now = datetime.now()
    # Very regular timing with CV < 0.1
    for i in range(10):
        action = {
            'action_type': 'collect',
            'location': 'zone_2',
            'timestamp': now + timedelta(milliseconds=i * 200)  # Exactly 200ms each time
        }
        result = analyzer.analyze_player_action('player_regular_bot', action)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)


def test_glitch_exploitation_detection():
    analyzer = GamingBehaviorAnalyzer()
    now = datetime.now()
    # Same location/action > 5 times
    for i in range(7):
        action = {
            'action_type': 'exploit_jump',
            'location': 'glitch_spot_A',
            'timestamp': now + timedelta(seconds=i * 30)
        }
        result = analyzer.analyze_player_action('player_glitch', action)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
    assert 'glitch' in result.threat_type.lower()


def test_account_farming_detection():
    analyzer = GamingBehaviorAnalyzer()
    accounts = [
        {'account_id': 'acc1', 'ip_address': '192.168.1.1', 'device_id': 'dev1'},
        {'account_id': 'acc2', 'ip_address': '192.168.1.1', 'device_id': 'dev2'},  # Same IP
        {'account_id': 'acc3', 'ip_address': '10.0.0.1', 'device_id': 'dev3'},
    ]
    links = analyzer.detect_account_links(accounts)
    assert len(links) > 0
    assert any(l['type'] == 'shared_ip' for l in links)


def test_collusion_detection():
    analyzer = GamingBehaviorAnalyzer()
    now = datetime.now()
    # Repeatedly losing to same opponent
    for i in range(6):
        action = {
            'action_type': 'match',
            'result': 'loss',
            'opponent_id': 'player_colluder',
            'timestamp': now + timedelta(hours=i)
        }
        result = analyzer.analyze_player_action('player_victim', action)
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
    assert 'collusion' in result.threat_type.lower()


def test_no_account_links_different_ips():
    analyzer = GamingBehaviorAnalyzer()
    accounts = [
        {'account_id': 'acc1', 'ip_address': '1.1.1.1', 'device_id': 'dev1'},
        {'account_id': 'acc2', 'ip_address': '2.2.2.2', 'device_id': 'dev2'},
    ]
    links = analyzer.detect_account_links(accounts)
    assert len(links) == 0
