from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime
import collections


@dataclass
class Pattern:
    pattern_type: str
    frequency: int
    confidence: float
    description: str
    severity: str


class PatternRecognizer:
    """Cross-domain threat pattern recognition with temporal analysis."""

    def recognize(self, action_sequence: list) -> List[Pattern]:
        """Recognize patterns in an action sequence."""
        if not action_sequence:
            return []

        patterns = []

        # Frequency analysis
        action_types = [a.get('action_type', a.get('type', 'unknown')) for a in action_sequence]
        type_counts = collections.Counter(action_types)

        for action_type, count in type_counts.items():
            if count > len(action_sequence) * 0.5:  # Dominant action type
                patterns.append(Pattern(
                    pattern_type='dominant_action',
                    frequency=count,
                    confidence=0.80,
                    description=f'Action type "{action_type}" dominates ({count}/{len(action_sequence)})',
                    severity='MEDIUM' if count > 10 else 'LOW'
                ))

        # Temporal clustering: burst of actions
        timestamps = []
        for a in action_sequence:
            ts = a.get('timestamp')
            if ts:
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts)
                timestamps.append(ts)

        if len(timestamps) >= 5:
            timestamps_sorted = sorted(timestamps)
            window_size = 10  # 10 seconds
            bursts = 0
            for i in range(len(timestamps_sorted)):
                window_end = timestamps_sorted[i].timestamp() + window_size
                window_count = sum(1 for t in timestamps_sorted[i:] if t.timestamp() <= window_end)
                if window_count >= 5:
                    bursts += 1

            if bursts > 0:
                patterns.append(Pattern(
                    pattern_type='temporal_burst',
                    frequency=bursts,
                    confidence=0.85,
                    description=f'Detected {bursts} action burst(s)',
                    severity='HIGH' if bursts > 3 else 'MEDIUM'
                ))

        # Repetition pattern
        if len(action_sequence) >= 3:
            sequence_strs = [str(sorted(a.items())) for a in action_sequence]
            repeat_counts = collections.Counter(sequence_strs)
            max_repeat = max(repeat_counts.values())
            if max_repeat > 3:
                patterns.append(Pattern(
                    pattern_type='exact_repetition',
                    frequency=max_repeat,
                    confidence=0.90,
                    description=f'Same action repeated {max_repeat} times',
                    severity='HIGH'
                ))

        return patterns
