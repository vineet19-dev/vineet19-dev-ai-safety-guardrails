from dataclasses import dataclass
from typing import List, Optional
import numpy as np
from scipy import stats as scipy_stats


@dataclass
class Anomaly:
    index: int
    value: float
    score: float
    method: str
    is_anomaly: bool


class AnomalyDetector:
    """Statistical anomaly detection using Z-score and IQR methods."""

    def detect(self, data_points: list, baseline: list = None) -> List[Anomaly]:
        """Detect anomalies in data_points using z-score and IQR.

        Z-score: |z| > 3.0 is anomalous
        IQR: value outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR] is anomalous
        """
        if not data_points:
            return []

        data = np.array(data_points, dtype=float)
        reference = np.array(baseline, dtype=float) if baseline else data

        anomalies = []

        if len(reference) < 2:
            return [Anomaly(index=i, value=float(v), score=0.0, method='insufficient_data', is_anomaly=False)
                    for i, v in enumerate(data)]

        # Z-score detection
        mean = np.mean(reference)
        std = np.std(reference)

        # IQR detection
        q1 = np.percentile(reference, 25)
        q3 = np.percentile(reference, 75)
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        for i, value in enumerate(data):
            z_score = abs((value - mean) / std) if std > 0 else 0
            iqr_anomaly = value < lower_bound or value > upper_bound
            z_anomaly = z_score > 3.0

            is_anomaly = z_anomaly or iqr_anomaly
            score = max(z_score, abs(value - mean) / (iqr if iqr > 0 else 1))

            anomalies.append(Anomaly(
                index=i,
                value=float(value),
                score=float(score),
                method='zscore_iqr',
                is_anomaly=is_anomaly
            ))

        return anomalies
