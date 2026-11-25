import math
from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest


class AdaptiveAnomalyDetector:
    """
    Hybrid ML + Adaptive Thresholding detector for per-client DNS behavior.
    Combines a pre-trained Global IsolationForest prior with a per-client
    sliding-window baseline to prevent both Cold-Start poisoning and Concept Drift.
    """

    def __init__(self, window_size: int = 20, blend_k: float = 8.0, z_multiplier: float = 2.5):
        self.window_size = window_size
        self.blend_k = blend_k
        self.z_multiplier = z_multiplier

        # Unsupervised Isolation Forest model
        self.model = IsolationForest(
            n_estimators=60,
            contamination=0.05,
            random_state=42,
        )

        # Per-client clean score history: client_id -> deque of clean anomaly scores
        self.client_histories: dict[str, deque[float]] = {}

        # Bootstrap global prior on synthetic normal traffic profiles
        self._fit_global_baseline()

    def _fit_global_baseline(self) -> None:
        """
        Trains the initial IsolationForest on representative normal DNS behavioral vectors:
        [request_rate, avg_entropy, max_domain_len, nxdomain_ratio, unique_domain_ratio]
        """
        rng = np.random.default_rng(42)
        n_samples = 250

        req_rate = rng.uniform(0.1, 8.0, size=n_samples)  # Normal browsing bursts
        avg_entropy = rng.uniform(1.5, 3.3, size=n_samples)  # Standard readable domains
        max_len = rng.uniform(6.0, 32.0, size=n_samples)  # Normal domain lengths
        nx_ratio = rng.uniform(0.0, 0.12, size=n_samples)  # Low NXDOMAIN rate
        unique_ratio = rng.uniform(0.1, 1.0, size=n_samples)  # Mix of repeated & single domains

        normal_X = np.column_stack([req_rate, avg_entropy, max_len, nx_ratio, unique_ratio])
        self.model.fit(normal_X)

        # Invert decision_function so higher score = more anomalous
        raw_scores = -self.model.decision_function(normal_X)
        mean_score = float(np.mean(raw_scores))
        std_score = float(np.std(raw_scores)) + 1e-6

        self.global_threshold = mean_score + (self.z_multiplier * std_score)

    def _get_client_threshold(self, client_id: str) -> tuple[float, float]:
        """
        Computes blended threshold: T_final = (1 - alpha) * T_global + alpha * T_local
        Returns (final_threshold, alpha_confidence)
        """
        history = self.client_histories.get(client_id)
        if not history:
            return self.global_threshold, 0.0

        n = len(history)
        alpha = n / (n + self.blend_k)

        local_arr = np.array(history, dtype=float)
        local_mean = float(np.mean(local_arr))
        local_std = float(np.std(local_arr)) + 0.02  # Floor prevents over-tightening on flat history
        local_threshold = max(local_mean + (self.z_multiplier * local_std), self.global_threshold * 0.85)

        final_threshold = ((1.0 - alpha) * self.global_threshold) + (alpha * local_threshold)
        return final_threshold, alpha

    def evaluate(self, client_id: str, features: list[float]) -> dict:
        """
        Evaluates a 5D feature vector for a client and updates clean history only if benign.
        features: [request_rate, avg_entropy, max_domain_len, nxdomain_ratio, unique_domain_ratio]
        """
        X = np.array([features], dtype=float)
        anomaly_score = float(-self.model.decision_function(X)[0])
        threshold, alpha = self._get_client_threshold(client_id)

        is_anomalous = anomaly_score > threshold

        # Anti-poisoning gate: only benign windows update the personal baseline
        if not is_anomalous:
            if client_id not in self.client_histories:
                self.client_histories[client_id] = deque(maxlen=self.window_size)
            self.client_histories[client_id].append(anomaly_score)

        return {
            "score": round(anomaly_score, 4),
            "threshold": round(threshold, 4),
            "alpha": round(alpha, 3),
            "is_anomalous": is_anomalous,
        }


def shannon_entropy(domain: str) -> float:
    """Calculates Shannon entropy of the primary domain label (to detect DGA randomness)."""
    parts = domain.split(".")
    target = parts[-2] if len(parts) >= 2 else domain
    if not target:
        return 0.0

    freq = {}
    for ch in target:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(target)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())