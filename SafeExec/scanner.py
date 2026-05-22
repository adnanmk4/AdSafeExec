"""
SafeExec - Core Scanner
Orchestrates all engines to produce a complete analysis report.
"""

import time
from engines import feature_extractor, ai_engine, rule_engine, threat_intelligence, decision_fusion, explanation_engine

# Shared ML model (loaded once)
_model = None


def get_model():
    global _model
    if _model is None:
        _model = ai_engine.load_model()
    return _model


def scan_file(filepath: str, progress_callback=None) -> dict:
    """
    Full pipeline scan of a file.
    Returns a comprehensive analysis report.
    """
    start_time = time.time()

    def progress(step: str, pct: int):
        if progress_callback:
            progress_callback(step, pct)

    progress("Extracting file features...", 10)

    # Step 1: Feature Extraction
    features = feature_extractor.extract_features(filepath)
    progress("Running AI prediction...", 30)

    # Step 2: AI Prediction
    model = get_model()
    ai_result = ai_engine.predict(features.get('ml_feature_vector', []), model=model)
    progress("Applying heuristic rules...", 55)

    # Step 3: Rule-Based Analysis
    rule_result = rule_engine.analyze(features)
    progress("Querying threat intelligence...", 72)

    # Step 4: Threat Intelligence
    ti_result = threat_intelligence.check(features)
    progress("Fusing decisions...", 85)

    # Step 5: Decision Fusion
    fusion_result = decision_fusion.fuse(ai_result, rule_result, ti_result, features)
    progress("Generating explanation...", 95)

    # Step 6: Explanation
    explanation = explanation_engine.generate_explanation(
        features, ai_result, rule_result, ti_result, fusion_result
    )

    elapsed = round(time.time() - start_time, 2)
    progress("Done!", 100)

    return {
        'filepath': filepath,
        'scan_time_seconds': elapsed,
        'features': features,
        'ai_result': ai_result,
        'rule_result': rule_result,
        'ti_result': ti_result,
        'fusion_result': fusion_result,
        'explanation': explanation
    }


def preload_model():
    """Preload model so first scan is fast."""
    get_model()
