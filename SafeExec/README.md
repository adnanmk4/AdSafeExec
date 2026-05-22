# 🛡 SafeExec — AI-Powered Pre-Execution Cyber Risk Analyzer

An educational hybrid AI + rule-based cybersecurity tool that analyzes files **before** execution to predict risk level.

---

## 🎯 Project Overview

SafeExec uses a **three-layer hybrid architecture** to classify files as Safe, Suspicious, or Dangerous:

| Layer | Engine | Weight |
|---|---|---|
| 🤖 AI/ML | RandomForest (scikit-learn) | 60% |
| 🔐 Heuristics | Rule-Based Engine | 30% |
| 🧠 Threat Intel | Local TI Database | 10% |

---

## 🚀 Quick Start

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python main.py
```

The AI model trains automatically on first run (~5 seconds).

---

## 🧩 Architecture

```
SafeExec/
├── main.py                     # Tkinter UI entry point
├── scanner.py                  # Orchestrator — runs full pipeline
├── requirements.txt
├── data/
│   └── threat_intelligence.json  # Local threat database
├── engines/
│   ├── feature_extractor.py    # File → ML feature vector
│   ├── ai_engine.py            # RandomForest ML model
│   ├── rule_engine.py          # Heuristic rule checks
│   ├── threat_intelligence.py  # Hash + pattern matching
│   ├── decision_fusion.py      # Weighted score fusion
│   └── explanation_engine.py   # Human-readable explanations
└── models/
    └── safeexec_model.pkl      # Trained model (auto-generated)
```

---

## 🤖 AI System

- **Model**: RandomForest (150 estimators)
- **Training**: Synthetic dataset (3,000 samples) with realistic feature distributions
- **Features** (16 total):
  - Extension risk score
  - File size (log-normalized)
  - Suspicious keyword presence & density
  - Double extension detection
  - Is executable / script
  - Long filename, unicode chars, multiple dots
  - System file name mimicry
  - File entropy (packed/encrypted detection)
  - Size anomalies (tiny executables, large scripts)
  - Modification time signals

---

## 🔐 Rule-Based Engine (10 Rules)

1. Extension risk profile
2. Suspicious filename keywords (crack, keygen, hack, etc.)
3. Double extension detection
4. System file name mimicry (svchost.exe, explorer.exe, etc.)
5. Tiny executable (dropper pattern)
6. Oversized script (embedded payload indicator)
7. High file entropy (packed/encrypted)
8. Unicode filename obfuscation (RLO attack detection)
9. Multiple dots in filename
10. Macro-enabled documents with suspicious names

---

## 🧠 Threat Intelligence Database

Located at `data/threat_intelligence.json`:
- Known malicious file hashes (MD5)
- Suspicious filename patterns (35+ patterns)
- Extension risk profiles with descriptions
- Known malware family names (ransomware, trojans, RATs, stealers)

---

## 📊 Decision Fusion

```
Final Risk Score = (AI Score × 0.60) + (Rule Score × 0.30) + (TI Score × 0.10)
```

| Score Range | Label |
|---|---|
| 0 – 34 | ✅ Safe |
| 35 – 64 | ⚠ Suspicious |
| 65 – 100 | 🚨 Dangerous |

---

## ⚠️ Limitations (Important)

- This is **NOT** a full antivirus or malware removal tool
- The AI model is trained on a **synthetic dataset** for educational purposes
- Detection is based on **file metadata and static features**, not runtime behavior
- No network communication or sandbox execution
- Purpose: **risk prediction + security awareness**, not deep malware analysis

---

## 🎓 Academic Use

This project demonstrates:
- Hybrid AI + rule-based cybersecurity system design
- Feature engineering for security classification
- Explainable AI in security contexts
- Decision fusion across multiple evidence sources
- User behavior awareness in security tools

---

## 📚 Tech Stack

- **Python 3.8+**
- **scikit-learn** — RandomForest classifier
- **Tkinter** — Desktop UI
- **JSON** — Threat intelligence database
- **hashlib** — File hashing
- **math** — Shannon entropy calculation
