"""
Behavior Monitoring System
==========================
Real-time action surveillance with pattern recognition for coordinated
unethical behaviour, anomaly scoring, and network analysis for collusion.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .ethical_framework import Action, Domain


@dataclass
class BehaviorRecord:
    action: Action
    timestamp: float = field(default_factory=time.time)
    anomaly_score: float = 0.0
    flags: list[str] = field(default_factory=list)


@dataclass
class CollusionNetwork:
    """Tracks relationships between actors for collusion detection."""

    actor_pairs: dict[frozenset[str], int] = field(
        default_factory=lambda: defaultdict(int)
    )

    def record_interaction(self, actor_a: str, actor_b: str) -> None:
        self.actor_pairs[frozenset({actor_a, actor_b})] += 1

    def get_interaction_count(self, actor_a: str, actor_b: str) -> int:
        return self.actor_pairs[frozenset({actor_a, actor_b})]

    def suspicious_pairs(self, threshold: int = 5) -> list[tuple[str, str, int]]:
        result = []
        for pair, count in self.actor_pairs.items():
            if count >= threshold:
                actors = list(pair)
                result.append((actors[0], actors[1] if len(actors) > 1 else "", count))
        return result


class BehaviorMonitor:
    """
    Monitors a stream of actions in real time.

    Maintains a rolling window of recent actions per actor and applies
    several anomaly-scoring heuristics:
      - High action frequency
      - Repeated identical action types
      - Coordinated timing between different actors
      - Escalating pattern of suspicious actions
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        frequency_threshold: int = 20,
        repetition_threshold: int = 5,
    ) -> None:
        self._window = window_seconds
        self._freq_threshold = frequency_threshold
        self._rep_threshold = repetition_threshold

        # actor_id -> deque of BehaviorRecords within window
        self._history: dict[str, deque[BehaviorRecord]] = defaultdict(deque)
        # domain -> deque of BehaviorRecords within window (for cross-actor analysis)
        self._domain_history: dict[Domain, deque[BehaviorRecord]] = defaultdict(deque)

        self._collusion_network = CollusionNetwork()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, action: Action) -> BehaviorRecord:
        """
        Record an incoming action and return a BehaviorRecord with an
        anomaly score and any detected flags.
        """
        record = BehaviorRecord(action=action)

        self._prune_history(action.actor_id)
        self._prune_domain_history(action.domain)

        record.flags, record.anomaly_score = self._analyze(action, record.timestamp)

        self._history[action.actor_id].append(record)
        self._domain_history[action.domain].append(record)

        return record

    def detect_collusion(
        self,
        actor_a: str,
        actor_b: str,
        interaction_threshold: int = 5,
    ) -> bool:
        """Return True when actor_a and actor_b have interacted suspiciously often."""
        self._collusion_network.record_interaction(actor_a, actor_b)
        count = self._collusion_network.get_interaction_count(actor_a, actor_b)
        return count >= interaction_threshold

    def get_actor_summary(self, actor_id: str) -> dict[str, Any]:
        self._prune_history(actor_id)
        records = list(self._history[actor_id])
        if not records:
            return {"actor_id": actor_id, "action_count": 0, "avg_anomaly_score": 0.0, "flags": []}

        all_flags: list[str] = []
        for r in records:
            all_flags.extend(r.flags)

        return {
            "actor_id": actor_id,
            "action_count": len(records),
            "avg_anomaly_score": round(
                sum(r.anomaly_score for r in records) / len(records), 3
            ),
            "flags": sorted(set(all_flags)),
        }

    def suspicious_pairs(self, threshold: int = 5) -> list[tuple[str, str, int]]:
        return self._collusion_network.suspicious_pairs(threshold)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _prune_history(self, actor_id: str) -> None:
        cutoff = time.time() - self._window
        dq = self._history[actor_id]
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()

    def _prune_domain_history(self, domain: Domain) -> None:
        cutoff = time.time() - self._window
        dq = self._domain_history[domain]
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()

    def _analyze(
        self, action: Action, now: float
    ) -> tuple[list[str], float]:
        flags: list[str] = []
        scores: list[float] = []

        actor_records = list(self._history[action.actor_id])

        # 1. High frequency
        freq = len(actor_records) + 1  # +1 for current
        if freq > self._freq_threshold:
            flags.append("high_frequency")
            scores.append(min(1.0, (freq - self._freq_threshold) / self._freq_threshold))

        # 2. Repetition of the same action type
        same_type = sum(1 for r in actor_records if r.action.action_type == action.action_type)
        if same_type >= self._rep_threshold:
            flags.append("repeated_action_type")
            scores.append(min(1.0, same_type / (self._rep_threshold * 2)))

        # 3. Coordinated timing: many actors in the same domain firing in short burst
        domain_records = list(self._domain_history[action.domain])
        recent_actors = {
            r.action.actor_id
            for r in domain_records
            if now - r.timestamp <= 5.0  # last 5 seconds
        }
        if len(recent_actors) >= 3 and action.actor_id not in recent_actors:
            flags.append("coordinated_timing_detected")
            scores.append(0.6)

        # 4. Escalating anomaly in actor history
        if len(actor_records) >= 3:
            recent_scores = [r.anomaly_score for r in list(actor_records)[-3:]]
            if all(recent_scores[i] < recent_scores[i + 1] for i in range(len(recent_scores) - 1)):
                flags.append("escalating_anomaly")
                scores.append(0.5)

        anomaly_score = round(
            1.0 - math.exp(-sum(scores)) if scores else 0.0, 3
        )
        return flags, anomaly_score
