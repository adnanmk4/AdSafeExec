"""
SafeExec - Threat Intelligence Engine
Matches file against known threat patterns and hashes.
"""

import json
import re
from pathlib import Path

THREAT_DB_PATH = Path(__file__).parent.parent / 'data' / 'threat_intelligence.json'
_db = None


def _load():
    global _db
    if _db is None:
        try:
            with open(THREAT_DB_PATH, 'r') as f:
                _db = json.load(f)
        except Exception:
            _db = {}
    return _db


def check(features: dict) -> dict:
    """
    Check file against threat intelligence database.
    Returns match results and threat score (0-100).
    """
    db = _load()
    matches = []
    score = 0

    md5 = features.get('hash_md5', '') or ''
    sha1 = features.get('hash_sha1', '') or ''
    sha256 = features.get('hash_sha256', '') or ''
    filename = features.get('filename', '').lower()
    ext = features.get('extension', '').lower()

    # --- Hash matching ---
    known_hashes = set(db.get('known_malicious_hashes', []))
    matched_hash = None
    for h in [md5, sha1, sha256]:
        if h and h in known_hashes:
            matched_hash = h
            break
    if matched_hash:
        score += 80
        matches.append({
            'type': 'Hash Match',
            'detail': f"File hash matches known malicious database entry: {matched_hash[:16]}...",
            'severity': 'CRITICAL',
            'score_added': 80
        })

    # --- Malware family name detection ---
    malware_families = db.get('known_malware_families', {})
    for family, names in malware_families.items():
        for name in names:
            if name in filename:
                score += 40
                matches.append({
                    'type': 'Malware Family Name',
                    'detail': f"Filename contains known {family} name: '{name}'",
                    'severity': 'CRITICAL',
                    'score_added': 40
                })
                break

    # --- Suspicious pattern matching ---
    sus_patterns = db.get('suspicious_filename_patterns', [])
    pattern_hits = [p for p in sus_patterns if p in filename]
    if pattern_hits:
        bonus = min(30, len(pattern_hits) * 10)
        score += bonus
        matches.append({
            'type': 'Threat Pattern Match',
            'detail': f"Filename matches threat patterns: {', '.join(pattern_hits)}",
            'severity': 'HIGH',
            'score_added': bonus
        })

    # --- Extension behavior profile match ---
    ext_profiles = db.get('dangerous_extensions', {})
    if ext in ext_profiles:
        ext_risk = ext_profiles[ext]['risk']
        if ext_risk >= 70:
            score += 15
            matches.append({
                'type': 'High-Risk Extension Profile',
                'detail': f"Extension '{ext}' is in threat intelligence high-risk list",
                'severity': 'MEDIUM',
                'score_added': 15
            })

    # --- No matches ---
    if not matches:
        matches.append({
            'type': 'No Threat Match',
            'detail': 'File not found in threat intelligence database',
            'severity': 'NONE',
            'score_added': 0
        })

    capped = min(100, score)
    return {
        'ti_score': capped,
        'ti_matches': matches,
        'hash_matched': matched_hash is not None,
        'match_count': len([m for m in matches if m['score_added'] > 0]),
        'ti_label': _label(capped)
    }


def _label(score: float) -> str:
    if score < 20: return 'Safe'
    if score < 50: return 'Suspicious'
    return 'Dangerous'
