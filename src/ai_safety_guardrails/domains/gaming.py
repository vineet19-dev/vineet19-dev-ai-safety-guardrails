from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import statistics
import collections

from ai_safety_guardrails.core.threat_level import ThreatLevel

# Maximum average action gap (ms) below which regularity-based bot detection is applied.
# Actions slower than this are not flagged purely for regularity (humans can be regular at slow speed).
BOT_DETECTION_MAX_AVG_GAP_MS = 500


@dataclass
class ThreatAssessment:
    threat_level: ThreatLevel
    threat_type: str
    confidence: float
    reasoning: str
    recommended_action: str


class GamingBehaviorAnalyzer:
    """Analyzer for detecting gaming behavior violations."""

    def __init__(self):
        self._player_actions: Dict[str, List[Dict]] = {}
        self._account_metadata: Dict[str, Dict] = {}

    def analyze_player_action(self, player_id: str, action: dict) -> ThreatAssessment:
        """Analyze a player action for suspicious behavior."""
        if player_id not in self._player_actions:
            self._player_actions[player_id] = []

        self._player_actions[player_id].append(action)
        history = self._player_actions[player_id]

        # Check botting: actions with <100ms average gap OR CV < 0.1 (too regular)
        timestamps = []
        for a in history:
            ts = a.get('timestamp', datetime.now())
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            timestamps.append(ts)

        if len(timestamps) >= 3:
            gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() * 1000
                    for i in range(len(timestamps)-1)]
            avg_gap = sum(gaps) / len(gaps)

            if avg_gap < 100:
                return ThreatAssessment(
                    threat_level=ThreatLevel.HIGH,
                    threat_type='botting',
                    confidence=0.90,
                    reasoning=f'Average action gap {avg_gap:.1f}ms < 100ms threshold',
                    recommended_action='flag_and_investigate'
                )

            # CV check: only flag if timing is fast (< BOT_DETECTION_MAX_AVG_GAP_MS) AND
            # suspiciously regular (CV < 0.1). Bots produce machine-precise timing at high speed;
            # a human can be slow but regular (e.g. taking a break), which should NOT be flagged.
            if len(gaps) >= 3 and avg_gap > 0 and avg_gap < BOT_DETECTION_MAX_AVG_GAP_MS:
                try:
                    cv = statistics.stdev(gaps) / avg_gap
                    if cv < 0.1:
                        return ThreatAssessment(
                            threat_level=ThreatLevel.HIGH,
                            threat_type='botting',
                            confidence=0.85,
                            reasoning=f'Action timing too regular (CV={cv:.3f} < 0.1)',
                            recommended_action='flag_and_investigate'
                        )
                except statistics.StatisticsError:
                    pass

        # Check glitch exploitation: same location/action > 5 times
        location = action.get('location')
        action_type = action.get('action_type')
        if location and action_type:
            same_pattern = [a for a in history
                            if a.get('location') == location and a.get('action_type') == action_type]
            if len(same_pattern) > 5:
                return ThreatAssessment(
                    threat_level=ThreatLevel.MEDIUM,
                    threat_type='glitch_exploitation',
                    confidence=0.80,
                    reasoning=f'Same location/action repeated {len(same_pattern)} times',
                    recommended_action='warn_player'
                )

        # Check collusion: losing intentionally to same opponent
        if action.get('result') == 'loss' and action.get('opponent_id'):
            opponent = action.get('opponent_id')
            losses_to_opponent = [a for a in history
                                  if a.get('result') == 'loss' and a.get('opponent_id') == opponent]
            if len(losses_to_opponent) >= 5:
                return ThreatAssessment(
                    threat_level=ThreatLevel.MEDIUM,
                    threat_type='collusion',
                    confidence=0.75,
                    reasoning=f'Lost to {opponent} {len(losses_to_opponent)} consecutive times',
                    recommended_action='investigate'
                )

        return ThreatAssessment(
            threat_level=ThreatLevel.LOW,
            threat_type='none',
            confidence=0.95,
            reasoning='No suspicious patterns detected',
            recommended_action='allow'
        )

    def detect_account_links(self, accounts: list) -> list:
        """Detect linked accounts (account farming)."""
        links = []
        ip_groups: Dict[str, list] = {}
        device_groups: Dict[str, list] = {}

        for account in accounts:
            ip = account.get('ip_address')
            device = account.get('device_id')
            acc_id = account.get('account_id')

            if ip:
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(acc_id)

            if device:
                if device not in device_groups:
                    device_groups[device] = []
                device_groups[device].append(acc_id)

        for ip, accs in ip_groups.items():
            if len(accs) > 1:
                links.append({
                    'type': 'shared_ip',
                    'shared_value': ip,
                    'accounts': accs,
                    'threat_level': 'HIGH'
                })

        for device, accs in device_groups.items():
            if len(accs) > 1:
                links.append({
                    'type': 'shared_device',
                    'shared_value': device,
                    'accounts': accs,
                    'threat_level': 'HIGH'
                })

        return links
