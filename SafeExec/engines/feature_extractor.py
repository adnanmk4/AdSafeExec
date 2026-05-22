"""
SafeExec - Feature Extraction Engine
Converts file metadata into ML-readable feature vectors.
"""

import os
import hashlib
import re
import json
import math
from pathlib import Path
from datetime import datetime


# Extensions categorized by type
SCRIPT_EXTENSIONS = {'.py', '.sh', '.bash', '.ps1', '.bat', '.cmd', '.vbs', '.js',
                     '.ts', '.rb', '.pl', '.php', '.lua', '.r', '.wsf', '.wsh', '.jse', '.vbe'}
EXECUTABLE_EXTENSIONS = {'.exe', '.com', '.pif', '.scr', '.dll', '.sys', '.msi',
                          '.jar', '.hta', '.lnk', '.app', '.run', '.elf'}
DOCUMENT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm',
                        '.ppt', '.pptx', '.rtf', '.odt', '.ods'}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.img', '.dmg'}
MEDIA_EXTENSIONS = {'.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac',
                    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'}
TEXT_EXTENSIONS = {'.txt', '.log', '.csv', '.json', '.xml', '.yaml', '.yml',
                   '.ini', '.cfg', '.conf', '.md', '.rst'}

SUSPICIOUS_KEYWORDS = [
    'crack', 'keygen', 'hack', 'patch', 'loader', 'bypass', 'exploit',
    'payload', 'inject', 'rootkit', 'trojan', 'worm', 'ransomware',
    'spyware', 'adware', 'backdoor', 'keylogger', 'botnet', 'dropper',
    'downloader', 'stealer', 'miner', 'cryptominer', 'rat', 'reverse',
    'activator', 'serial', 'nulled', 'cracked', 'pirated', 'leaked',
    'free_premium', 'no_survey', 'undetected', 'fud', 'bypass_av'
]


def compute_file_hash(filepath: str) -> dict:
    """Compute MD5, SHA1, SHA256 of file."""
    hashes = {'md5': None, 'sha1': None, 'sha256': None}
    try:
        h_md5 = hashlib.md5()
        h_sha1 = hashlib.sha1()
        h_sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
        hashes['md5'] = h_md5.hexdigest()
        hashes['sha1'] = h_sha1.hexdigest()
        hashes['sha256'] = h_sha256.hexdigest()
    except Exception:
        pass
    return hashes


def get_file_type_category(extension: str) -> str:
    """Return human-readable file type category."""
    ext = extension.lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return 'executable'
    elif ext in SCRIPT_EXTENSIONS:
        return 'script'
    elif ext in DOCUMENT_EXTENSIONS:
        return 'document'
    elif ext in ARCHIVE_EXTENSIONS:
        return 'archive'
    elif ext in MEDIA_EXTENSIONS:
        return 'media'
    elif ext in TEXT_EXTENSIONS:
        return 'text'
    else:
        return 'unknown'


def calculate_entropy(filepath: str) -> float:
    """Calculate Shannon entropy of the file (high entropy = possible encryption/packing)."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(65536)  # Read first 64KB
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


def extract_features(filepath: str) -> dict:
    """
    Main feature extraction function.
    Returns a rich feature dictionary for ML and rule-based analysis.
    """
    path = Path(filepath)
    features = {}

    # --- Basic File Info ---
    features['filename'] = path.name
    features['extension'] = path.suffix.lower()
    features['filepath'] = str(filepath)

    # --- File Size ---
    try:
        size = os.path.getsize(filepath)
    except Exception:
        size = 0
    features['file_size_bytes'] = size
    features['file_size_kb'] = round(size / 1024, 2)

    # --- Extension Risk Category ---
    ext = path.suffix.lower()
    features['file_type_category'] = get_file_type_category(ext)

    # Binary risk categories for ML
    features['is_executable'] = int(ext in EXECUTABLE_EXTENSIONS)
    features['is_script'] = int(ext in SCRIPT_EXTENSIONS)
    features['is_document'] = int(ext in DOCUMENT_EXTENSIONS)
    features['is_archive'] = int(ext in ARCHIVE_EXTENSIONS)
    features['is_media'] = int(ext in MEDIA_EXTENSIONS)
    features['is_text'] = int(ext in TEXT_EXTENSIONS)
    features['is_unknown_type'] = int(features['file_type_category'] == 'unknown')

    # --- Double Extension Detection ---
    name_no_ext = path.stem
    double_ext = bool(re.search(r'\.\w{2,4}$', name_no_ext))
    features['has_double_extension'] = int(double_ext)
    if double_ext:
        inner_ext = Path(name_no_ext).suffix.lower()
        features['double_extension_inner'] = inner_ext
        # Especially suspicious if hiding as safe type
        features['double_ext_hiding_safe'] = int(inner_ext in MEDIA_EXTENSIONS | TEXT_EXTENSIONS)
    else:
        features['double_extension_inner'] = ''
        features['double_ext_hiding_safe'] = 0

    # --- Suspicious Keyword Detection in Filename ---
    filename_lower = path.name.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in filename_lower]
    features['suspicious_keyword_count'] = len(found_keywords)
    features['suspicious_keywords_found'] = found_keywords
    features['has_suspicious_keywords'] = int(len(found_keywords) > 0)

    # --- Filename Anomalies ---
    # Check for very long filename
    features['filename_length'] = len(path.name)
    features['has_long_filename'] = int(len(path.name) > 100)

    # Check for unicode/special chars (obfuscation)
    features['has_unicode_chars'] = int(not all(ord(c) < 128 for c in path.name))

    # Check for multiple dots
    features['dot_count'] = path.name.count('.')
    features['has_multiple_dots'] = int(path.name.count('.') > 2)

    # Looks like system file
    features['mimics_system_file'] = int(any(
        name in filename_lower for name in
        ['svchost', 'explorer', 'winlogon', 'csrss', 'lsass', 'services']
    ))

    # --- File Hash ---
    hashes = compute_file_hash(filepath)
    features['hash_md5'] = hashes['md5']
    features['hash_sha1'] = hashes['sha1']
    features['hash_sha256'] = hashes['sha256']

    # --- Entropy ---
    features['entropy'] = calculate_entropy(filepath)
    features['high_entropy'] = int(features['entropy'] > 7.0)  # Packed/encrypted

    # --- File Modification Time ---
    try:
        mtime = os.path.getmtime(filepath)
        mod_time = datetime.fromtimestamp(mtime)
        features['file_modified_timestamp'] = mtime
        features['file_modified_human'] = mod_time.strftime('%Y-%m-%d %H:%M:%S')
        # Files modified at odd hours (simulated risk signal)
        features['modified_odd_hour'] = int(mod_time.hour < 5 or mod_time.hour > 22)
    except Exception:
        features['file_modified_timestamp'] = 0
        features['file_modified_human'] = 'Unknown'
        features['modified_odd_hour'] = 0

    # --- Size Anomaly ---
    is_executable_or_script = features['is_executable'] or features['is_script']
    features['suspiciously_small_executable'] = int(
        is_executable_or_script and size < 5120 and size > 0
    )
    features['suspiciously_large_script'] = int(
        features['is_script'] and size > 1_000_000
    )

    # --- ML-ready numeric feature vector ---
    features['ml_feature_vector'] = _build_ml_vector(features)

    return features


def _build_ml_vector(features: dict) -> list:
    """
    Build a numeric feature vector for ML model input.
    Returns a list of floats.
    """
    # Extension base risk scores (normalized 0-1)
    ext_risk_map = {
        'executable': 0.9,
        'script': 0.7,
        'document': 0.3,
        'archive': 0.25,
        'text': 0.05,
        'media': 0.05,
        'unknown': 0.5
    }
    ext_risk = ext_risk_map.get(features.get('file_type_category', 'unknown'), 0.5)

    # File size normalized (log scale, capped at 1)
    size_bytes = features.get('file_size_bytes', 0)
    size_norm = min(math.log10(size_bytes + 1) / 10, 1.0)

    vector = [
        ext_risk,                                               # 0: Extension risk
        size_norm,                                              # 1: File size (log normalized)
        features.get('has_suspicious_keywords', 0),            # 2: Has suspicious keywords
        min(features.get('suspicious_keyword_count', 0) / 5, 1.0),  # 3: Keyword density
        features.get('has_double_extension', 0),               # 4: Double extension
        features.get('double_ext_hiding_safe', 0),             # 5: Hiding as safe type
        features.get('is_executable', 0),                      # 6: Is executable
        features.get('is_script', 0),                          # 7: Is script
        features.get('has_long_filename', 0),                  # 8: Long filename
        features.get('has_unicode_chars', 0),                  # 9: Unicode obfuscation
        features.get('has_multiple_dots', 0),                  # 10: Multiple dots
        features.get('mimics_system_file', 0),                 # 11: System file mimicry
        features.get('high_entropy', 0),                       # 12: High entropy
        features.get('suspiciously_small_executable', 0),      # 13: Tiny executable
        features.get('suspiciously_large_script', 0),          # 14: Large script
        features.get('modified_odd_hour', 0),                  # 15: Modified at odd hour
    ]

    return vector


def get_feature_names() -> list:
    """Return names of ML feature vector columns."""
    return [
        'extension_risk', 'file_size_normalized', 'has_suspicious_keywords',
        'keyword_density', 'has_double_extension', 'double_ext_hiding_safe',
        'is_executable', 'is_script', 'has_long_filename', 'has_unicode_chars',
        'has_multiple_dots', 'mimics_system_file', 'high_entropy',
        'suspiciously_small_executable', 'suspiciously_large_script', 'modified_odd_hour'
    ]
