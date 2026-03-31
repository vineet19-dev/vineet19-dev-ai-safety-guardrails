import pytest
import numpy as np
from ai_safety_guardrails.detection.anomaly_detector import AnomalyDetector, Anomaly
from ai_safety_guardrails.detection.network_analyzer import NetworkAnalyzer, Network, Cluster
from ai_safety_guardrails.detection.pattern_recognizer import PatternRecognizer, Pattern
from datetime import datetime, timedelta


class TestAnomalyDetector:
    def test_no_anomalies_uniform_data(self):
        detector = AnomalyDetector()
        data = [10.0, 11.0, 10.5, 9.5, 10.2, 10.8, 9.8, 10.3]
        result = detector.detect(data)
        assert isinstance(result, list)
        anomalies = [a for a in result if a.is_anomaly]
        assert len(anomalies) == 0

    def test_detects_outlier(self):
        detector = AnomalyDetector()
        data = [10.0, 11.0, 10.5, 9.5, 10.2, 10.8, 9.8, 100.0]  # Last is outlier
        result = detector.detect(data)
        assert any(a.is_anomaly for a in result)
        # The outlier should be at the last index
        assert result[-1].is_anomaly == True

    def test_with_baseline(self):
        detector = AnomalyDetector()
        baseline = [10.0, 11.0, 10.5, 9.5, 10.2]
        new_data = [10.1, 50.0]  # 50.0 is anomalous against baseline
        result = detector.detect(new_data, baseline)
        assert len(result) == 2
        assert result[1].is_anomaly == True

    def test_empty_data(self):
        detector = AnomalyDetector()
        result = detector.detect([])
        assert result == []

    def test_anomaly_score(self):
        detector = AnomalyDetector()
        data = [10.0] * 10 + [100.0]
        result = detector.detect(data)
        # Last element should have high anomaly score
        assert result[-1].score > result[0].score


class TestNetworkAnalyzer:
    def test_build_network(self):
        analyzer = NetworkAnalyzer()
        entities = ['A', 'B', 'C']
        relationships = [('A', 'B'), ('B', 'C')]
        network = analyzer.build_network(entities, relationships)
        assert isinstance(network, Network)
        assert len(network.entities) == 3

    def test_detect_collusion_clusters(self):
        analyzer = NetworkAnalyzer()
        entities = ['A', 'B', 'C', 'D']
        # A, B, C are tightly connected (potential collusion)
        relationships = [('A', 'B'), ('B', 'C'), ('A', 'C')]
        network = analyzer.build_network(entities, relationships)
        clusters = analyzer.detect_collusion_clusters(network)
        assert len(clusters) > 0
        # The cluster with A, B, C should be the most suspicious
        main_cluster = clusters[0]
        assert len(main_cluster.members) >= 3

    def test_find_suspicious_connections(self):
        analyzer = NetworkAnalyzer()
        entities = ['hub', 'A', 'B', 'C', 'D', 'E']
        # Hub has many connections
        relationships = [('hub', 'A'), ('hub', 'B'), ('hub', 'C'), ('hub', 'D'), ('hub', 'E')]
        network = analyzer.build_network(entities, relationships)
        suspicious = analyzer.find_suspicious_connections('A', network)
        assert isinstance(suspicious, list)

    def test_empty_network(self):
        analyzer = NetworkAnalyzer()
        network = analyzer.build_network([], [])
        clusters = analyzer.detect_collusion_clusters(network)
        assert clusters == []


class TestPatternRecognizer:
    def test_recognize_dominant_action(self):
        recognizer = PatternRecognizer()
        actions = [{'action_type': 'buy', 'amount': 100} for _ in range(10)]
        actions += [{'action_type': 'sell', 'amount': 50}]
        patterns = recognizer.recognize(actions)
        assert any(p.pattern_type == 'dominant_action' for p in patterns)

    def test_recognize_temporal_burst(self):
        recognizer = PatternRecognizer()
        now = datetime.now()
        # 10 actions within 5 seconds
        actions = [
            {'action_type': 'click', 'timestamp': now + timedelta(milliseconds=i * 400)}
            for i in range(10)
        ]
        patterns = recognizer.recognize(actions)
        assert any(p.pattern_type == 'temporal_burst' for p in patterns)

    def test_empty_sequence(self):
        recognizer = PatternRecognizer()
        patterns = recognizer.recognize([])
        assert patterns == []

    def test_recognize_repetition(self):
        recognizer = PatternRecognizer()
        base_action = {'action_type': 'exploit', 'location': 'spot_1', 'target': 'glitch'}
        actions = [base_action.copy() for _ in range(5)]
        patterns = recognizer.recognize(actions)
        assert any(p.pattern_type == 'exact_repetition' for p in patterns)
