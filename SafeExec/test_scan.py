"""
SafeExec - CLI Test Runner
Test the analysis pipeline without launching the GUI.
Usage: python test_scan.py <filepath>
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scanner


def print_separator(char="─", width=60):
    print(char * width)


def print_result(result: dict):
    fusion  = result['fusion_result']
    ai      = result['ai_result']
    rules   = result['rule_result']
    ti      = result['ti_result']
    feats   = result['features']
    expl    = result['explanation']

    label   = fusion['final_label']
    score   = fusion['risk_score']
    conf    = fusion['confidence']

    ICONS = {'Safe': '✅', 'Suspicious': '⚠️ ', 'Dangerous': '🚨'}

    print_separator("═")
    print(f"  SafeExec Analysis Report")
    print_separator("═")

    print(f"\nFile     : {feats['filename']}")
    print(f"Type     : {feats['file_type_category']} ({feats['extension']})")
    print(f"Size     : {feats['file_size_kb']} KB")
    print(f"Entropy  : {feats['entropy']}")
    print(f"MD5      : {feats.get('hash_md5', 'N/A')}")

    print_separator()
    print(f"\n  {ICONS.get(label, '?')} VERDICT: {label.upper()}")
    print(f"  Risk Score  : {score:.1f} / 100")
    print(f"  Confidence  : {conf:.1f}%")
    print(f"  Scan Time   : {result['scan_time_seconds']}s")

    print_separator()
    print("\n🤖 AI ENGINE")
    print(f"  Model      : {ai['model_type']}")
    print(f"  Prediction : {ai['label']} ({ai['confidence']:.1f}% confidence)")
    print(f"  Prob Safe  : {ai['prob_safe']:.1f}%")
    print(f"  Prob Sus   : {ai['prob_suspicious']:.1f}%")
    print(f"  Prob Dan   : {ai['prob_dangerous']:.1f}%")

    print_separator()
    print("\n🔐 HEURISTIC RULES")
    print(f"  Score: {rules['heuristic_score']:.0f}/100  Label: {rules['heuristic_label']}")
    for rule in rules['triggered_rules']:
        if rule['score_added'] > 0:
            print(f"  [{rule['severity']}] {rule['rule']}: {rule['detail']}")

    print_separator()
    print("\n🧠 THREAT INTELLIGENCE")
    print(f"  TI Score   : {ti['ti_score']:.0f}/100")
    print(f"  Hash Match : {'YES ⚠' if ti['hash_matched'] else 'No'}")
    for m in ti['ti_matches']:
        if m['score_added'] > 0:
            print(f"  [{m['severity']}] {m['type']}: {m['detail']}")

    print_separator()
    print("\n📋 SUMMARY")
    print(f"  {expl['summary']}")

    print_separator()
    print("\n💡 RECOMMENDATIONS")
    for rec in expl['recommendations']:
        print(f"  {rec}")

    print_separator("═")


def demo_scan():
    """Run a demo scan on a created temp file."""
    import tempfile

    # Create a suspiciously-named test file
    test_cases = [
        ("safe_document.txt", b"This is a normal text file with no threat signals."),
        ("invoice.pdf.exe", b"MZ" + b"\x00" * 100),  # Double extension, exe header
        ("keygen_crack_activator.bat", b"@echo off\necho cracking...\n"),
    ]

    print("\n" + "═" * 60)
    print("  SafeExec — Demo Scan (3 test files)")
    print("═" * 60)

    for filename, content in test_cases:
        with tempfile.NamedTemporaryFile(suffix="_" + filename, delete=False) as f:
            f.write(content)
            tmppath = f.name

        try:
            # Rename so the filename features are realistic
            real_path = os.path.join(os.path.dirname(tmppath), filename)
            os.rename(tmppath, real_path)

            print(f"\n→ Scanning: {filename}")
            result = scanner.scan_file(real_path)
            fusion = result['fusion_result']
            ai = result['ai_result']
            print(f"  Verdict: {fusion['final_label']} | Score: {fusion['risk_score']:.1f}/100 | AI: {ai['label']} ({ai['confidence']:.0f}%)")

            os.unlink(real_path)
        except Exception as e:
            print(f"  Error: {e}")
            try: os.unlink(tmppath)
            except: pass

    print("\n" + "═" * 60)
    print("  Demo complete. Run 'python main.py' for the full UI.")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if not os.path.exists(filepath):
            print(f"Error: File not found: {filepath}")
            sys.exit(1)
        print(f"\nScanning: {filepath}")
        result = scanner.scan_file(filepath, progress_callback=lambda s, p: print(f"  [{p:3d}%] {s}"))
        print_result(result)
    else:
        print("No file specified — running demo scan...")
        demo_scan()
