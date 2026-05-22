"""
SafeExec - Rule-Based Heuristic Engine
Applies cybersecurity expert rules to score file risk.
"""

import json
import os
from pathlib import Path

THREAT_DB_PATH = Path(__file__).parent.parent / 'data' / 'threat_intelligence.json'

_threat_db = None

def _load_threat_db():
    global _threat_db
    if _threat_db is None:
        try:
            with open(THREAT_DB_PATH, 'r') as f:
                _threat_db = json.load(f)
        except Exception:
            _threat_db = {}
    return _threat_db


def analyze(features: dict) -> dict:
    """
    Apply all heuristic rules to extracted features.
    Returns rule scores, triggered rules, and total heuristic score (0-100).
    """
    db = _load_threat_db()
    triggered_rules = []
    total_score = 0

    ext = features.get('extension', '').lower()
    filename = features.get('filename', '').lower()
    size = features.get('file_size_bytes', 0)

    # --- Rule 1: Extension Risk ---
    ext_profiles = db.get('dangerous_extensions', {})
    if ext in ext_profiles:
        ext_risk = ext_profiles[ext]['risk']
        ext_desc = ext_profiles[ext]['description']
        weighted = ext_risk * 0.4
        total_score += weighted
        triggered_rules.append({
            'rule': 'Extension Risk',
            'detail': f"Extension '{ext}' — {ext_desc}",
            'score_added': round(weighted, 1),
            'severity': _severity(ext_risk)
        })

    # --- Rule 2: Suspicious Keywords ---
    sus_patterns = db.get('suspicious_filename_patterns', [])
    found_kws = [kw for kw in sus_patterns if kw in filename]
    if found_kws:
        kw_score = min(30, len(found_kws) * 10)
        total_score += kw_score
        triggered_rules.append({
            'rule': 'Suspicious Filename Keywords',
            'detail': f"Found keywords: {', '.join(found_kws)}",
            'score_added': kw_score,
            'severity': _severity(kw_score)
        })

    # --- Rule 3: Double Extension ---
    if features.get('has_double_extension'):
        score = 20
        if features.get('double_ext_hiding_safe'):
            score = 35
            detail = f"Hiding executable as safe type (inner: {features.get('double_extension_inner', '')})"
        else:
            detail = "Double file extension detected"
        total_score += score
        triggered_rules.append({
            'rule': 'Double Extension',
            'detail': detail,
            'score_added': score,
            'severity': _severity(score * 2)
        })

    # --- Rule 4: System File Mimicry ---
    if features.get('mimics_system_file'):
        score = 30
        total_score += score
        triggered_rules.append({
            'rule': 'System File Name Mimicry',
            'detail': "Filename resembles a critical Windows system process",
            'score_added': score,
            'severity': 'HIGH'
        })

    # --- Rule 5: Suspicious Size ---
    if features.get('suspiciously_small_executable'):
        score = 15
        total_score += score
        triggered_rules.append({
            'rule': 'Tiny Executable',
            'detail': f"Executable is only {features.get('file_size_kb', 0)} KB — common in dropper malware",
            'score_added': score,
            'severity': 'MEDIUM'
        })

    if features.get('suspiciously_large_script'):
        score = 10
        total_score += score
        triggered_rules.append({
            'rule': 'Oversized Script',
            'detail': f"Script is {features.get('file_size_kb', 0)} KB — may contain embedded payload",
            'score_added': score,
            'severity': 'MEDIUM'
        })

    # --- Rule 6: High Entropy ---
    entropy = features.get('entropy', 0)
    if entropy > 7.5:
        score = 20
        total_score += score
        triggered_rules.append({
            'rule': 'High File Entropy',
            'detail': f"Entropy={entropy:.2f} — file may be encrypted, packed, or obfuscated",
            'score_added': score,
            'severity': 'HIGH'
        })
    elif entropy > 7.0:
        score = 10
        total_score += score
        triggered_rules.append({
            'rule': 'Elevated File Entropy',
            'detail': f"Entropy={entropy:.2f} — slightly elevated, possible packing",
            'score_added': score,
            'severity': 'LOW'
        })

    # --- Rule 7: Unicode/Obfuscated Filename ---
    if features.get('has_unicode_chars'):
        score = 15
        total_score += score
        triggered_rules.append({
            'rule': 'Unicode Filename Obfuscation',
            'detail': "Filename contains non-ASCII characters — possible RLO attack or obfuscation",
            'score_added': score,
            'severity': 'HIGH'
        })

    # --- Rule 8: Multiple Dots ---
    if features.get('has_multiple_dots') and not features.get('has_double_extension'):
        score = 8
        total_score += score
        triggered_rules.append({
            'rule': 'Multiple Dots in Filename',
            'detail': "Excessive dots in filename — possible obfuscation attempt",
            'score_added': score,
            'severity': 'LOW'
        })

    # --- Rule 9: Executable in unusual category (document or archive extension wrapping exe) ---
    if features.get('is_executable') and features.get('double_ext_hiding_safe'):
        score = 20
        total_score += score
        triggered_rules.append({
            'rule': 'Hidden Executable',
            'detail': "File appears to be a media/document but has an executable extension",
            'score_added': score,
            'severity': 'CRITICAL'
        })

    # --- Rule 10: Macro-enabled documents with suspicious keywords ---
    if ext in {'.xlsm', '.docm', '.xlam'} and found_kws:
        score = 20
        total_score += score
        triggered_rules.append({
            'rule': 'Macro Document + Suspicious Name',
            'detail': "Macro-enabled document with suspicious filename — common phishing vector",
            'score_added': score,
            'severity': 'HIGH'
        })

    # --- No rules triggered = low risk ---
    if not triggered_rules:
        triggered_rules.append({
            'rule': 'No Rules Triggered',
            'detail': "File passed all heuristic checks",
            'score_added': 0,
            'severity': 'NONE'
        })

    capped_score = min(100, round(total_score, 1))

    return {
        'heuristic_score': capped_score,
        'triggered_rules': triggered_rules,
        'rule_count': len([r for r in triggered_rules if r['score_added'] > 0]),
        'heuristic_label': _label_from_score(capped_score)
    }


def _severity(score: float) -> str:
    if score >= 70: return 'CRITICAL'
    if score >= 50: return 'HIGH'
    if score >= 30: return 'MEDIUM'
    if score >= 10: return 'LOW'
    return 'INFO'


def _label_from_score(score: float) -> str:
    if score < 30: return 'Safe'
    if score < 60: return 'Suspicious'
    return 'Dangerous'
