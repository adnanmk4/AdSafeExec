# AdSafeExec

SafeExec is an educational hybrid cybersecurity tool that analyzes files before execution using AI, heuristic rules, and local threat intelligence. It is designed to highlight file risk and explain why a file may be labeled Safe, Suspicious, or Dangerous.

---

## 🚀 What it does

SafeExec scans a selected file and generates an analysis report with:
- A risk verdict (`Safe`, `Suspicious`, or `Dangerous`)
- A risk score and confidence estimate
- AI-based prediction from a trained RandomForest model
- Rule-based heuristic checks for suspicious file properties
- Threat intelligence lookup from a local JSON database
- A human-readable explanation of the findings

---

## 🧠 Architecture

The scanner orchestrates multiple engines:
- `engines/feature_extractor.py` — converts a file into a feature vector
- `engines/ai_engine.py` — loads and runs the RandomForest model
- `engines/rule_engine.py` — applies heuristic security rules
- `engines/threat_intelligence.py` — checks hashes, names, and patterns
- `engines/decision_fusion.py` — combines AI, rules, and TI scores
- `engines/explanation_engine.py` — builds the final explanation

The UI is implemented in `main.py`, and `scanner.py` performs the full scan pipeline.

---

## ⚙️ Requirements

- Python 3.8+
- `scikit-learn>=1.3.0`
- `numpy>=1.24.0`

Install dependencies with:

```bash
pip install -r SafeExec/requirements.txt
```

---

## ▶️ Run SafeExec

From the repository root:

```bash
python SafeExec/main.py
```

The app opens a Tkinter UI where you can browse for a file, analyze it, and review the risk verdict.

---

## 📦 Project Layout

```text
SafeExec/
├── main.py
├── scanner.py
├── requirements.txt
├── data/
│   └── threat_intelligence.json
├── engines/
│   ├── ai_engine.py
│   ├── decision_fusion.py
│   ├── explanation_engine.py
│   ├── feature_extractor.py
│   ├── rule_engine.py
│   └── threat_intelligence.py
├── models/
└── test_scan.py
```

---

## 🧪 Testing

Run the built-in scanner test from the project root:

```bash
python SafeExec/test_scan.py
```

---

## ⚠️ Limitations

- This is not a production antivirus solution.
- The model is trained for demonstration and educational purposes.
- Detection is based on static features, not runtime behavior or sandboxing.
- Use SafeExec as a security awareness tool, not as a definitive malware scanner.

---

## 💡 Notes

- `SafeExec/requirements.txt` contains the dependencies.
- `SafeExec/data/threat_intelligence.json` stores local threat intelligence used during scanning.
- The model is loaded and reused for faster scans.

- <img height="200" alt="image" src="https://github.com/user-attachments/assets/1a6d7b93-788c-4bd7-b878-1a3ea45c8b06" />



