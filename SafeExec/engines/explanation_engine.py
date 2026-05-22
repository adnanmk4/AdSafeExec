"""
SafeExec - Explanation Engine
Generates human-readable security explanations from analysis results.
"""

from engines.feature_extractor import get_feature_names
from engines.ai_engine import get_top_contributing_features


def generate_explanation(
    features: dict,
    ai_result: dict,
    rule_result: dict,
    ti_result: dict,
    fusion_result: dict
) -> dict:
    """
    Generate a complete, human-readable explanation of the analysis.
    """
    label = fusion_result.get('final_label', 'Unknown')
    score = fusion_result.get('risk_score', 0)
    filename = features.get('filename', 'Unknown file')
    ext = features.get('extension', '')
    category = features.get('file_type_category', 'unknown')

    # --- Summary sentence ---
    summary = _build_summary(label, score, filename, features, ai_result, rule_result, ti_result)

    # --- AI explanation ---
    ai_explanation = _build_ai_explanation(ai_result, features)

    # --- Rule explanations ---
    rule_explanations = _build_rule_explanations(rule_result)

    # --- Threat intelligence explanation ---
    ti_explanation = _build_ti_explanation(ti_result)

    # --- Threat scenario ---
    threat_scenario = _build_threat_scenario(label, features, rule_result)

    # --- Recommended actions ---
    recommendations = _build_recommendations(label, features, score)

    # --- Top contributing features ---
    top_features = get_top_contributing_features(
        features.get('ml_feature_vector', []),
        get_feature_names(),
        ai_result.get('feature_importances', [])
    )

    return {
        'summary': summary,
        'ai_explanation': ai_explanation,
        'rule_explanations': rule_explanations,
        'ti_explanation': ti_explanation,
        'threat_scenario': threat_scenario,
        'recommendations': recommendations,
        'top_contributing_features': top_features
    }


def _build_summary(label, score, filename, features, ai_result, rule_result, ti_result) -> str:
    triggered = rule_result.get('rule_count', 0)
    ti_matches = ti_result.get('match_count', 0)
    ai_label = ai_result.get('label', 'Unknown')
    category = features.get('file_type_category', 'file')

    parts = [f'"{filename}" was analyzed as a {category} and classified as {label.upper()} (Risk Score: {score}/100).']

    if label == 'Dangerous':
        parts.append(
            f'The AI model predicted {ai_label} with {ai_result.get("confidence", 0):.0f}% confidence, '
            f'{triggered} heuristic rule(s) triggered alerts, and {ti_matches} threat intelligence match(es) were found.'
        )
        parts.append('This file exhibits multiple characteristics associated with malicious software. Exercise extreme caution.')
    elif label == 'Suspicious':
        parts.append(
            f'The AI model predicted {ai_label} with {ai_result.get("confidence", 0):.0f}% confidence, '
            f'and {triggered} heuristic rule(s) raised concerns.'
        )
        parts.append('This file has some risk indicators. Verify its origin before proceeding.')
    else:
        parts.append(
            f'The AI model predicted Safe with {ai_result.get("confidence", 0):.0f}% confidence, '
            f'and no significant heuristic rules were triggered.'
        )
        parts.append('No major threats were detected. Standard caution still applies.')

    return ' '.join(parts)


def _build_ai_explanation(ai_result: dict, features: dict) -> str:
    label = ai_result.get('label', 'Unknown')
    conf = ai_result.get('confidence', 0)
    model = ai_result.get('model_type', 'ML Model')
    prob_safe = ai_result.get('prob_safe', 0)
    prob_sus = ai_result.get('prob_suspicious', 0)
    prob_dan = ai_result.get('prob_dangerous', 0)

    explanation = (
        f'The {model} analyzed 16 engineered features from this file and predicted: {label} '
        f'with {conf:.1f}% confidence. '
        f'Probability breakdown — Safe: {prob_safe:.1f}%, Suspicious: {prob_sus:.1f}%, '
        f'Dangerous: {prob_dan:.1f}%. '
    )

    # Key features that drove the prediction
    fv = features.get('ml_feature_vector', [])
    key_signals = []
    if len(fv) > 6 and fv[6] > 0.5:
        key_signals.append('executable file type')
    if len(fv) > 2 and fv[2] > 0.5:
        key_signals.append('suspicious filename keywords')
    if len(fv) > 4 and fv[4] > 0.5:
        key_signals.append('double extension')
    if len(fv) > 12 and fv[12] > 0.5:
        key_signals.append('high file entropy')
    if len(fv) > 11 and fv[11] > 0.5:
        key_signals.append('system file name mimicry')

    if key_signals:
        explanation += f'Key features driving this prediction: {", ".join(key_signals)}.'
    else:
        explanation += 'No single dominant feature drove this prediction — risk is low across all dimensions.'

    return explanation


def _build_rule_explanations(rule_result: dict) -> list:
    rules = rule_result.get('triggered_rules', [])
    explanations = []
    for rule in rules:
        if rule.get('score_added', 0) > 0:
            explanations.append(
                f"[{rule['severity']}] {rule['rule']}: {rule['detail']} (+{rule['score_added']} pts)"
            )
    return explanations if explanations else ['No heuristic rules were triggered.']


def _build_ti_explanation(ti_result: dict) -> str:
    matches = ti_result.get('ti_matches', [])
    score = ti_result.get('ti_score', 0)
    count = ti_result.get('match_count', 0)

    if count == 0:
        return 'Threat intelligence scan found no matches in the known malicious database.'

    lines = [f'Threat intelligence found {count} match(es) (TI Score: {score}/100):']
    for m in matches:
        if m.get('score_added', 0) > 0:
            lines.append(f'  • [{m["severity"]}] {m["type"]}: {m["detail"]}')
    return '\n'.join(lines)


def _build_threat_scenario(label: str, features: dict, rule_result: dict) -> str:
    ext = features.get('extension', '').lower()
    category = features.get('file_type_category', '')

    if label == 'Safe':
        return (
            'If executed, this file is unlikely to cause harm based on current analysis. '
            'However, even safe files can be used in multi-stage attacks — always verify the source.'
        )

    scenarios = []

    if features.get('has_double_extension'):
        scenarios.append(
            'The double extension technique is commonly used in phishing attacks. '
            'A file like "invoice.pdf.exe" appears to be a PDF but executes as a program, '
            'potentially installing ransomware, a RAT, or data stealer silently.'
        )

    if features.get('has_suspicious_keywords'):
        scenarios.append(
            'Files distributed as cracks, keygens, or activators frequently bundle malware. '
            'Upon execution, they may install cryptocurrency miners, steal credentials, '
            'or establish persistent backdoor access to your system.'
        )

    if category == 'executable' and label == 'Dangerous':
        scenarios.append(
            'Executing this file could allow it to: modify system registry, '
            'disable security software, exfiltrate sensitive data, encrypt files (ransomware), '
            'or establish command-and-control communication.'
        )

    if features.get('high_entropy'):
        scenarios.append(
            'The high entropy indicates this file may be packed or obfuscated to evade antivirus detection. '
            'Packed malware unpacks itself at runtime, making static analysis unreliable.'
        )

    if features.get('mimics_system_file'):
        scenarios.append(
            'Mimicking system process names (svchost, explorer, etc.) is a classic persistence technique. '
            'The malware hides in plain sight among legitimate processes in Task Manager.'
        )

    if not scenarios:
        scenarios.append(
            'If executed, this file may perform unauthorized actions based on its risk profile. '
            'The combination of detected risk signals warrants caution before proceeding.'
        )

    return ' '.join(scenarios)


def _build_recommendations(label: str, features: dict, score: float) -> list:
    recommendations = []

    if label == 'Dangerous':
        recommendations += [
            '🚫 DO NOT execute or open this file.',
            '🗑️ Delete the file immediately if it was downloaded from an untrusted source.',
            '🔍 Scan with a reputable antivirus (Windows Defender, Malwarebytes) before any action.',
            '🌐 If the file came via email, report it as phishing to your IT/security team.',
            '💾 If already executed, isolate the system from the network immediately.',
        ]
    elif label == 'Suspicious':
        recommendations += [
            '⚠️ Proceed with extreme caution before opening or executing.',
            '🔍 Scan with an updated antivirus or upload to VirusTotal (virustotal.com).',
            '📁 Verify the file source and confirm it was sent intentionally.',
            '🔒 Consider opening in a sandboxed environment or virtual machine.',
        ]
    else:
        recommendations += [
            '✅ File appears safe based on current analysis.',
            '🔁 Still verify the source before executing any file.',
            '🛡️ Keep your operating system and antivirus software up to date.',
        ]

    return recommendations
