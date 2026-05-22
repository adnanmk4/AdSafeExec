"""
SafeExec - Decision Fusion Engine
Combines AI, rule-based, and threat intelligence scores
into a single final risk decision.
"""


# Fusion weights
AI_WEIGHT = 0.60
RULE_WEIGHT = 0.30
TI_WEIGHT = 0.10

LABEL_TO_SCORE = {'Safe': 15, 'Suspicious': 55, 'Dangerous': 90}
SCORE_THRESHOLDS = {'Safe': 35, 'Suspicious': 65}


def fuse(ai_result: dict, rule_result: dict, ti_result: dict, features: dict) -> dict:
    """
    Fuse all engine results into a final risk decision.

    Returns:
        final_label: Safe / Suspicious / Dangerous
        risk_score: 0-100
        confidence: percentage
        breakdown: per-engine contribution
        user_behavior_signals: context-aware advisory
    """

    # --- Convert AI prediction to numeric score ---
    ai_label = ai_result.get('label', 'Suspicious')
    ai_confidence = ai_result.get('confidence', 50) / 100
    ai_base = LABEL_TO_SCORE.get(ai_label, 55)
    # Blend toward confidence: high confidence = stay near base; low = pull toward center
    ai_score = ai_base * ai_confidence + 50 * (1 - ai_confidence)

    # --- Rule score ---
    rule_score = rule_result.get('heuristic_score', 0)

    # --- Threat intelligence score ---
    ti_score = ti_result.get('ti_score', 0)

    # --- Weighted fusion ---
    fused = (ai_score * AI_WEIGHT) + (rule_score * RULE_WEIGHT) + (ti_score * TI_WEIGHT)
    fused = round(min(100, max(0, fused)), 1)

    # --- Hash match override: always dangerous ---
    if ti_result.get('hash_matched'):
        fused = max(fused, 90)

    # --- Final label from fused score ---
    if fused < SCORE_THRESHOLDS['Safe']:
        final_label = 'Safe'
    elif fused < SCORE_THRESHOLDS['Suspicious']:
        final_label = 'Suspicious'
    else:
        final_label = 'Dangerous'

    # --- Confidence: agreement across engines ---
    labels = [ai_label, rule_result.get('heuristic_label'), ti_result.get('ti_label')]
    agreement = labels.count(final_label)
    confidence = 50 + (agreement - 1) * 20 + (ai_result.get('confidence', 50) - 50) * 0.3
    confidence = round(min(99, max(30, confidence)), 1)

    # --- User Behavior Awareness ---
    behavior_signals = _user_behavior_signals(features, final_label, fused)

    # --- Breakdown ---
    breakdown = {
        'ai_score': round(ai_score, 1),
        'ai_weight': AI_WEIGHT,
        'ai_contribution': round(ai_score * AI_WEIGHT, 1),
        'rule_score': rule_score,
        'rule_weight': RULE_WEIGHT,
        'rule_contribution': round(rule_score * RULE_WEIGHT, 1),
        'ti_score': ti_score,
        'ti_weight': TI_WEIGHT,
        'ti_contribution': round(ti_score * TI_WEIGHT, 1),
    }

    return {
        'final_label': final_label,
        'risk_score': fused,
        'confidence': confidence,
        'breakdown': breakdown,
        'user_behavior_signals': behavior_signals,
        'engine_labels': {
            'ai': ai_label,
            'rules': rule_result.get('heuristic_label'),
            'threat_intel': ti_result.get('ti_label')
        }
    }


def _user_behavior_signals(features: dict, label: str, score: float) -> list:
    """Generate user-facing behavioral risk advisories."""
    signals = []
    ext = features.get('extension', '').lower()
    category = features.get('file_type_category', 'unknown')

    if category == 'executable' and label != 'Safe':
        signals.append({
            'signal': 'Execution Risk',
            'advice': 'Running this file directly grants it full access to your system. Verify the source before executing.',
            'level': 'HIGH'
        })

    if features.get('has_double_extension'):
        signals.append({
            'signal': 'Deceptive Filename',
            'advice': 'This file disguises its true type using a double extension — a common social engineering trick.',
            'level': 'HIGH'
        })

    if features.get('has_suspicious_keywords'):
        signals.append({
            'signal': 'Piracy/Crack Indicator',
            'advice': 'Files advertised as cracks or keygens are among the most common malware distribution vectors.',
            'level': 'HIGH'
        })

    if score > 60:
        signals.append({
            'signal': 'Unknown Source Risk',
            'advice': 'If this file was downloaded from an untrusted source, the risk level is significantly higher.',
            'level': 'MEDIUM'
        })

    if features.get('high_entropy'):
        signals.append({
            'signal': 'Obfuscation Detected',
            'advice': 'High file entropy suggests the file may be packed or encrypted — a common malware evasion technique.',
            'level': 'MEDIUM'
        })

    if not signals:
        signals.append({
            'signal': 'Standard Precautions',
            'advice': 'Even safe-looking files should come from trusted sources. Verify before opening.',
            'level': 'INFO'
        })

    return signals
