"""
SafeExec - AI Prediction Engine
Trains and runs the ML model for risk prediction.
Uses RandomForest with a synthetic training dataset.
"""

import os
import json
import pickle
import random
import numpy as np
from pathlib import Path

# Try sklearn; if unavailable, use fallback
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

MODEL_PATH = Path(__file__).parent.parent / 'models' / 'safeexec_model.pkl'
LABELS = {0: 'Safe', 1: 'Suspicious', 2: 'Dangerous'}
LABEL_COLORS = {'Safe': '#00c853', 'Suspicious': '#ffd600', 'Dangerous': '#d50000'}


def _generate_synthetic_dataset(n_samples: int = 2000):
    """
    Generate a realistic synthetic training dataset.
    Features: [ext_risk, size_norm, has_sus_kw, kw_density, double_ext,
                hiding_safe, is_exec, is_script, long_fn, unicode, multi_dot,
                mimic_sys, high_entropy, tiny_exec, large_script, odd_hour]
    Labels: 0=Safe, 1=Suspicious, 2=Dangerous
    """
    random.seed(42)
    np.random.seed(42)
    X, y = [], []

    def add(features, label, n=1, noise=0.05):
        for _ in range(n):
            f = [max(0, min(1, v + random.gauss(0, noise))) for v in features]
            X.append(f)
            y.append(label)

    # --- SAFE samples (label=0) ---
    # Text files, images, media
    for _ in range(n_samples // 4):
        add([0.05, random.random() * 0.5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, noise=0.03)
    # Normal documents
    for _ in range(n_samples // 8):
        add([0.3, random.random() * 0.6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, noise=0.05)
    # Legitimate executables (no suspicious traits)
    for _ in range(n_samples // 8):
        add([0.85, random.random() * 0.7, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, noise=0.06)

    # --- SUSPICIOUS samples (label=1) ---
    # Script with suspicious keywords
    for _ in range(n_samples // 6):
        add([0.7, random.random() * 0.5, 1, random.random() * 0.4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], 1, noise=0.07)
    # Archive with suspicious name
    for _ in range(n_samples // 8):
        add([0.25, random.random() * 0.6, 1, random.random() * 0.3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, noise=0.06)
    # Executable with one red flag
    for _ in range(n_samples // 8):
        add([0.9, random.random() * 0.3, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0], 1, noise=0.07)
    # Document with macros + keyword
    for _ in range(n_samples // 8):
        add([0.6, random.random() * 0.4, 1, 0.2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, noise=0.06)
    # High entropy archive
    for _ in range(n_samples // 10):
        add([0.25, 0.5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], 1, noise=0.05)

    # --- DANGEROUS samples (label=2) ---
    # Double extension hiding executable as image
    for _ in range(n_samples // 6):
        add([0.9, random.random() * 0.3, 1, 0.6, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0], 2, noise=0.05)
    # Executable + all flags
    for _ in range(n_samples // 6):
        add([0.9, random.random() * 0.2, 1, 0.8, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1], 2, noise=0.04)
    # Script mimicking system file
    for _ in range(n_samples // 8):
        add([0.7, random.random() * 0.2, 1, 0.4, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1], 2, noise=0.05)
    # Tiny executable (dropper pattern)
    for _ in range(n_samples // 8):
        add([0.9, 0.05, 1, 0.5, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0], 2, noise=0.04)
    # High-risk script with all signals
    for _ in range(n_samples // 10):
        add([0.75, 0.3, 1, 0.9, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0], 2, noise=0.04)

    return np.array(X), np.array(y)


def train_model(force_retrain: bool = False) -> object:
    """Train the RandomForest model and save to disk."""
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    if MODEL_PATH.exists() and not force_retrain:
        return load_model()

    if not SKLEARN_AVAILABLE:
        return None

    print("[AI Engine] Training RandomForest model on synthetic dataset...")
    X, y = _generate_synthetic_dataset(n_samples=3000)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=5,
            random_state=42,
            class_weight='balanced'
        ))
    ])
    model.fit(X_train, y_train)

    # Evaluation
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=['Safe', 'Suspicious', 'Dangerous'])
    print("[AI Engine] Model Training Complete!\n", report)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    print(f"[AI Engine] Model saved to {MODEL_PATH}")
    return model


def load_model() -> object:
    """Load trained model from disk."""
    if not MODEL_PATH.exists():
        return train_model()
    try:
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    except Exception:
        return train_model(force_retrain=True)


def predict(feature_vector: list, model=None) -> dict:
    """
    Run AI prediction on a feature vector.
    Returns: {label, confidence, probabilities, feature_importances}
    """
    if model is None:
        model = load_model()

    if model is None or not SKLEARN_AVAILABLE:
        return _fallback_prediction(feature_vector)

    try:
        X = np.array([feature_vector])
        pred_class = int(model.predict(X)[0])
        proba = model.predict_proba(X)[0]
        label = LABELS[pred_class]
        confidence = float(proba[pred_class])

        # Feature importances from RandomForest
        importances = []
        try:
            rf = model.named_steps['clf']
            imp = rf.feature_importances_
            importances = [round(float(v), 4) for v in imp]
        except Exception:
            pass

        return {
            'label': label,
            'predicted_class': pred_class,
            'confidence': round(confidence * 100, 1),
            'prob_safe': round(float(proba[0]) * 100, 1),
            'prob_suspicious': round(float(proba[1]) * 100, 1),
            'prob_dangerous': round(float(proba[2]) * 100, 1),
            'feature_importances': importances,
            'model_type': 'RandomForest',
            'sklearn_available': True
        }
    except Exception as e:
        return _fallback_prediction(feature_vector, error=str(e))


def _fallback_prediction(feature_vector: list, error: str = None) -> dict:
    """Rule-based fallback when sklearn is unavailable."""
    # Simple weighted sum
    weights = [0.15, 0.05, 0.1, 0.08, 0.12, 0.1, 0.12, 0.08, 0.02, 0.05, 0.03, 0.05, 0.05, 0.1, 0.05, 0.03]
    if len(feature_vector) < len(weights):
        feature_vector = feature_vector + [0] * (len(weights) - len(feature_vector))
    score = sum(f * w for f, w in zip(feature_vector[:len(weights)], weights))

    if score < 0.25:
        label, pred_class = 'Safe', 0
        confidence = (0.25 - score) / 0.25 * 60 + 40
    elif score < 0.55:
        label, pred_class = 'Suspicious', 1
        confidence = 55 + (score - 0.25) * 40
    else:
        label, pred_class = 'Dangerous', 2
        confidence = min(95, 60 + (score - 0.55) * 80)

    return {
        'label': label,
        'predicted_class': pred_class,
        'confidence': round(confidence, 1),
        'prob_safe': round(max(0, (0.3 - score) * 200), 1),
        'prob_suspicious': round(max(0, 100 - abs(score - 0.4) * 300), 1),
        'prob_dangerous': round(max(0, (score - 0.4) * 200), 1),
        'feature_importances': [],
        'model_type': 'Fallback (no sklearn)',
        'sklearn_available': False,
        'error': error
    }


def get_top_contributing_features(feature_vector: list, feature_names: list, importances: list, top_n: int = 5) -> list:
    """Return top N features contributing to the prediction."""
    if not importances or len(importances) != len(feature_vector):
        return []
    contributions = []
    for i, (name, val, imp) in enumerate(zip(feature_names, feature_vector, importances)):
        if val > 0:
            contributions.append({
                'feature': name,
                'value': round(val, 3),
                'importance': round(imp, 4),
                'contribution': round(val * imp, 5)
            })
    contributions.sort(key=lambda x: x['contribution'], reverse=True)
    return contributions[:top_n]
