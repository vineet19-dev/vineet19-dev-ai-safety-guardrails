import pytest
from datetime import datetime, timedelta
from ai_safety_guardrails.core.ethical_framework import EthicsClassifier, Domain
from ai_safety_guardrails.core.behavior_monitor import BehaviorMonitor
from ai_safety_guardrails.core.audit_logger import AuditLogger
from ai_safety_guardrails.domains.financial_trading import FinancialTradingMonitor, ThreatLevel
from ai_safety_guardrails.domains.gaming import GamingBehaviorAnalyzer
from ai_safety_guardrails.detection.anomaly_detector import AnomalyDetector
from ai_safety_guardrails.detection.network_analyzer import NetworkAnalyzer
from ai_safety_guardrails.prevention.action_blocker import ActionBlocker
from ai_safety_guardrails.prevention.constraint_enforcer import ConstraintEnforcer, Constraint


class TestFullPipeline:
    """Integration tests for the full AI safety guardrails pipeline."""

    def test_financial_trading_full_pipeline(self):
        """Test complete financial trading detection and prevention pipeline."""
        monitor = FinancialTradingMonitor()
        blocker = ActionBlocker()
        logger = AuditLogger()

        now = datetime.now()

        # Step 1: First trade (buy)
        buy_trade = {
            'agent_id': 'trader_1',
            'asset': 'AAPL',
            'side': 'buy',
            'amount': 100,
            'timestamp': now
        }
        threat1 = monitor.analyze_trade(buy_trade)
        decision1 = blocker.evaluate_and_block(buy_trade, threat1)
        logger.log_decision({'trade': buy_trade, 'threat': threat1.threat_type, 'blocked': decision1.should_block})

        assert decision1.should_block == False  # Legitimate first trade

        # Step 2: Wash trade (sell same asset within 60 seconds)
        sell_trade = {
            'agent_id': 'trader_1',
            'asset': 'AAPL',
            'side': 'sell',
            'amount': 100,
            'timestamp': now + timedelta(seconds=30)
        }
        threat2 = monitor.analyze_trade(sell_trade)
        decision2 = blocker.evaluate_and_block(sell_trade, threat2)
        logger.log_decision({'trade': sell_trade, 'threat': threat2.threat_type, 'blocked': decision2.should_block})

        assert threat2.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
        assert decision2.should_block == True

        # Step 3: Verify audit trail
        trail = logger.get_audit_trail()
        assert len(trail) == 2

    def test_behavior_monitoring_integration(self):
        """Test behavior monitoring detects escalating patterns."""
        monitor = BehaviorMonitor()
        logger = AuditLogger()

        agent_id = 'agent_escalating'

        # Record increasing severity actions
        for i in range(5):
            action = {
                'action_type': 'trade',
                'amount': 1000 * (i + 1),
                'risk_level': 'high' if i > 2 else 'low'
            }
            monitor.record_action(agent_id, action)

        history = monitor.get_behavior_history(agent_id)
        assert len(history) == 5

        patterns = monitor.detect_anomalous_patterns(agent_id)
        assert isinstance(patterns, list)

        # Log to audit
        logger.log_decision({
            'agent_id': agent_id,
            'anomalous_patterns': len(patterns),
            'action': 'monitored'
        })

        report = logger.export_compliance_report()
        assert isinstance(report, dict)

    def test_anomaly_detection_integration(self):
        """Test anomaly detection integrated with network analysis."""
        detector = AnomalyDetector()
        analyzer = NetworkAnalyzer()

        # Detect volume anomalies
        volumes = [100, 105, 98, 102, 99, 101, 98, 1000]  # Last is anomalous
        anomalies = detector.detect(volumes)
        assert any(a.is_anomaly for a in anomalies)

        # Find network of related entities
        entities = ['A', 'B', 'C', 'D']
        relationships = [('A', 'B'), ('B', 'C'), ('C', 'A')]  # Triangle = suspicious
        network = analyzer.build_network(entities, relationships)
        clusters = analyzer.detect_collusion_clusters(network)

        assert len(clusters) > 0

    def test_gaming_full_pipeline(self):
        """Test gaming behavior detection pipeline."""
        analyzer = GamingBehaviorAnalyzer()
        blocker = ActionBlocker()

        now = datetime.now()
        player_id = 'bot_player'

        results = []
        for i in range(8):
            action = {
                'action_type': 'attack',
                'location': 'zone_1',
                'timestamp': now + timedelta(milliseconds=i * 30)  # 30ms gaps = botting
            }
            threat = analyzer.analyze_player_action(player_id, action)
            decision = blocker.evaluate_and_block(action, threat)
            results.append((threat, decision))

        # Eventually should detect botting
        final_threat, final_decision = results[-1]
        assert final_threat.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)

    def test_ethics_classifier_integration(self):
        """Test ethics classifier with various domains."""
        classifier = EthicsClassifier()

        # Financial domain
        financial_action = {
            'domain': 'FINANCIAL',
            'action_type': 'standard_trade',
            'transparent': True
        }
        result = classifier.classify(financial_action)
        assert result.is_ethical == True

        # Unethical action
        unethical_action = {
            'domain': 'BUSINESS',
            'action_type': 'contract',
            'contains_fraud': True,
            'deceptive': True
        }
        result2 = classifier.classify(unethical_action)
        assert result2.is_ethical == False

    def test_constraint_enforcement_integration(self):
        """Test constraint enforcement across domains."""
        enforcer = ConstraintEnforcer()

        # Add financial constraints
        enforcer.add_constraint('financial', Constraint(
            name='max_trade',
            domain='financial',
            constraint_type='amount_limit',
            parameters={'max_amount': 50000}
        ))

        # Compliant action
        action1 = {'domain': 'financial', 'action_type': 'trade', 'amount': 10000}
        result1 = enforcer.enforce(action1)
        assert result1.is_compliant == True

        # Violating action
        action2 = {'domain': 'financial', 'action_type': 'trade', 'amount': 100000}
        result2 = enforcer.enforce(action2)
        assert result2.is_compliant == False

    def test_audit_compliance_report(self):
        """Test audit logger produces valid compliance report."""
        logger = AuditLogger()

        for i in range(10):
            logger.log_decision({
                'decision_id': f'd{i}',
                'action_type': 'trade' if i % 2 == 0 else 'block',
                'severity': 'HIGH' if i > 7 else 'LOW',
                'domain': 'FINANCIAL'
            })

        trail = logger.get_audit_trail()
        assert len(trail) == 10

        report = logger.export_compliance_report()
        assert isinstance(report, dict)
        assert 'total_decisions' in report or len(report) > 0

        # Filter by domain
        filtered = logger.get_audit_trail({'domain': 'FINANCIAL'})
        assert len(filtered) == 10
