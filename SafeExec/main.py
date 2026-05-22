"""
SafeExec - AI-Powered Pre-Execution Cyber Risk Analyzer
Main UI Application (Tkinter)
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scanner

# ─── Color Palette ───────────────────────────────────────────────
BG_DARK      = "#0d1117"
BG_CARD      = "#161b22"
BG_CARD2     = "#21262d"
ACCENT_BLUE  = "#58a6ff"
ACCENT_CYAN  = "#39d353"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"

COLOR_SAFE       = "#39d353"
COLOR_SUSPICIOUS = "#e3b341"
COLOR_DANGEROUS  = "#f85149"
COLOR_NEUTRAL    = "#58a6ff"

FONT_MONO  = ("Consolas", 10)
FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_LABEL = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)

LABEL_COLORS = {
    "Safe":       COLOR_SAFE,
    "Suspicious": COLOR_SUSPICIOUS,
    "Dangerous":  COLOR_DANGEROUS
}


class SafeExecApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SafeExec — AI Cyber Risk Analyzer")
        self.geometry("1100x780")
        self.minsize(900, 650)
        self.configure(bg=BG_DARK)
        self.resizable(True, True)

        self._scan_result = None
        self._scanning = False

        self._build_ui()
        self._preload_model()

    # ─── UI BUILD ─────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_file_selector()
        self._build_progress()
        self._build_results_area()
        self._build_footer()

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_DARK, pady=16)
        hdr.pack(fill="x", padx=24)

        tk.Label(hdr, text="🛡  SafeExec", font=FONT_TITLE,
                 bg=BG_DARK, fg=TEXT_PRIMARY).pack(side="left")
        tk.Label(hdr, text="AI-Powered Pre-Execution Cyber Risk Analyzer",
                 font=("Segoe UI", 11), bg=BG_DARK, fg=TEXT_MUTED).pack(side="left", padx=14, pady=6)

        badge = tk.Label(hdr, text=" AI + Rules + TI ", font=FONT_SMALL,
                         bg="#1f6feb", fg="white", padx=6, pady=2, relief="flat")
        badge.pack(side="right")

    def _build_file_selector(self):
        frame = tk.Frame(self, bg=BG_CARD, padx=16, pady=14, relief="flat")
        frame.pack(fill="x", padx=24, pady=(0, 10))
        self._add_border(frame)

        top = tk.Frame(frame, bg=BG_CARD)
        top.pack(fill="x")

        tk.Label(top, text="Select File to Analyze", font=FONT_BOLD,
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(side="left")

        self.btn_browse = tk.Button(
            top, text="📂  Browse File", command=self._browse_file,
            bg="#238636", fg="white", font=FONT_BOLD,
            relief="flat", padx=12, pady=4, cursor="hand2",
            activebackground="#2ea043", activeforeground="white"
        )
        self.btn_browse.pack(side="right")

        self.btn_scan = tk.Button(
            top, text="🔍  Analyze", command=self._start_scan,
            bg="#1f6feb", fg="white", font=FONT_BOLD,
            relief="flat", padx=12, pady=4, cursor="hand2",
            activebackground="#388bfd", activeforeground="white",
            state="disabled"
        )
        self.btn_scan.pack(side="right", padx=(0, 8))

        # File info bar
        info = tk.Frame(frame, bg=BG_CARD2, padx=10, pady=8, relief="flat")
        info.pack(fill="x", pady=(10, 0))

        self.lbl_filepath = tk.Label(info, text="No file selected",
                                     font=FONT_MONO, bg=BG_CARD2, fg=TEXT_MUTED,
                                     anchor="w", wraplength=700)
        self.lbl_filepath.pack(side="left", fill="x", expand=True)

        self.lbl_filesize = tk.Label(info, text="", font=FONT_SMALL,
                                     bg=BG_CARD2, fg=ACCENT_BLUE)
        self.lbl_filesize.pack(side="right")

    def _build_progress(self):
        pf = tk.Frame(self, bg=BG_DARK)
        pf.pack(fill="x", padx=24, pady=(0, 6))

        self.lbl_status = tk.Label(pf, text="Ready", font=FONT_SMALL,
                                   bg=BG_DARK, fg=TEXT_MUTED)
        self.lbl_status.pack(side="left")

        self.progressbar = ttk.Progressbar(pf, length=200, mode="determinate")
        self.progressbar.pack(side="right")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TProgressbar", troughcolor=BG_CARD2, background=ACCENT_BLUE, thickness=6)

    def _build_results_area(self):
        self.results_outer = tk.Frame(self, bg=BG_DARK)
        self.results_outer.pack(fill="both", expand=True, padx=24, pady=(0, 10))

        # Left: verdict + metadata
        self.left_frame = tk.Frame(self.results_outer, bg=BG_DARK)
        self.left_frame.pack(side="left", fill="both", expand=False, padx=(0, 8))
        self.left_frame.configure(width=330)
        self.left_frame.pack_propagate(False)

        self._build_verdict_card()
        self._build_metadata_card()

        # Right: explanation tabs
        self.right_frame = tk.Frame(self.results_outer, bg=BG_DARK)
        self.right_frame.pack(side="left", fill="both", expand=True)

        self._build_tabs()

    def _build_verdict_card(self):
        card = tk.Frame(self.left_frame, bg=BG_CARD, padx=14, pady=14)
        card.pack(fill="x", pady=(0, 8))
        self._add_border(card)

        tk.Label(card, text="VERDICT", font=("Segoe UI", 8, "bold"),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w")

        self.lbl_verdict = tk.Label(card, text="—", font=("Segoe UI", 32, "bold"),
                                    bg=BG_CARD, fg=TEXT_MUTED)
        self.lbl_verdict.pack(anchor="w", pady=(4, 0))

        self.lbl_verdict_desc = tk.Label(card, text="Awaiting scan",
                                         font=FONT_SMALL, bg=BG_CARD, fg=TEXT_MUTED, wraplength=280, anchor="w")
        self.lbl_verdict_desc.pack(anchor="w")

        sep = tk.Frame(card, bg=BORDER, height=1)
        sep.pack(fill="x", pady=10)

        # Score meter
        self._build_score_meter(card)

        sep2 = tk.Frame(card, bg=BORDER, height=1)
        sep2.pack(fill="x", pady=10)

        # Confidence + engine agreement
        conf_row = tk.Frame(card, bg=BG_CARD)
        conf_row.pack(fill="x")
        tk.Label(conf_row, text="Confidence:", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.lbl_confidence = tk.Label(conf_row, text="—", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_PRIMARY)
        self.lbl_confidence.pack(side="right")

        scan_row = tk.Frame(card, bg=BG_CARD)
        scan_row.pack(fill="x", pady=(4, 0))
        tk.Label(scan_row, text="Scan Time:", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.lbl_scantime = tk.Label(scan_row, text="—", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_PRIMARY)
        self.lbl_scantime.pack(side="right")

    def _build_score_meter(self, parent):
        tk.Label(parent, text="RISK SCORE", font=("Segoe UI", 8, "bold"),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w")

        self.canvas_meter = tk.Canvas(parent, width=290, height=28,
                                      bg=BG_CARD, highlightthickness=0)
        self.canvas_meter.pack(anchor="w", pady=(4, 2))
        self._draw_meter(0, "—")

        self.lbl_score_num = tk.Label(parent, text="Score: —",
                                      font=("Segoe UI", 11, "bold"), bg=BG_CARD, fg=TEXT_PRIMARY)
        self.lbl_score_num.pack(anchor="w")

    def _draw_meter(self, score: float, label: str):
        c = self.canvas_meter
        c.delete("all")
        w, h = 290, 28
        r = 8

        # Track
        c.create_rectangle(0, 8, w, 22, fill=BG_CARD2, outline="", width=0)

        # Gradient fill
        if score > 0:
            fill_w = int((score / 100) * w)
            if score < 40:
                color = COLOR_SAFE
            elif score < 65:
                color = COLOR_SUSPICIOUS
            else:
                color = COLOR_DANGEROUS
            c.create_rectangle(0, 8, fill_w, 22, fill=color, outline="", width=0)

        # Score text
        c.create_text(w // 2, 15, text=f"{score:.0f} / 100",
                      font=("Segoe UI", 9, "bold"), fill=TEXT_PRIMARY)

    def _build_metadata_card(self):
        card = tk.Frame(self.left_frame, bg=BG_CARD, padx=14, pady=12)
        card.pack(fill="x")
        self._add_border(card)

        tk.Label(card, text="FILE METADATA", font=("Segoe UI", 8, "bold"),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w", pady=(0, 8))

        self.meta_rows = {}
        meta_fields = [
            ("Filename", "filename"),
            ("Extension", "extension"),
            ("File Type", "file_type_category"),
            ("Size", "file_size_kb"),
            ("MD5", "hash_md5"),
            ("Entropy", "entropy"),
            ("Modified", "file_modified_human"),
        ]
        for display, key in meta_fields:
            row = tk.Frame(card, bg=BG_CARD)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"{display}:", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_MUTED,
                     width=10, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="—", font=FONT_SMALL, bg=BG_CARD,
                           fg=TEXT_PRIMARY, anchor="w", wraplength=160)
            lbl.pack(side="left", fill="x", expand=True)
            self.meta_rows[key] = lbl

    def _build_tabs(self):
        style = ttk.Style()
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_CARD2, foreground=TEXT_MUTED,
                        padding=[12, 6], font=FONT_SMALL)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_CARD)],
                  foreground=[("selected", TEXT_PRIMARY)])

        self.notebook = ttk.Notebook(self.right_frame)
        self.notebook.pack(fill="both", expand=True)

        self.tab_summary     = self._make_tab("📋 Summary")
        self.tab_ai          = self._make_tab("🤖 AI Engine")
        self.tab_rules       = self._make_tab("🔐 Rules")
        self.tab_ti          = self._make_tab("🧠 Threat Intel")
        self.tab_behavior    = self._make_tab("👤 Behavior")
        self.tab_recommend   = self._make_tab("💡 Actions")

    def _make_tab(self, title: str) -> scrolledtext.ScrolledText:
        frame = tk.Frame(self.notebook, bg=BG_CARD)
        self.notebook.add(frame, text=title)
        txt = scrolledtext.ScrolledText(frame, bg=BG_CARD, fg=TEXT_PRIMARY,
                                        font=FONT_MONO, wrap="word",
                                        relief="flat", padx=14, pady=12,
                                        insertbackground=TEXT_PRIMARY,
                                        state="disabled")
        txt.pack(fill="both", expand=True)
        # Tag styles
        txt.tag_configure("heading", font=("Segoe UI", 11, "bold"), foreground=ACCENT_BLUE)
        txt.tag_configure("safe", foreground=COLOR_SAFE)
        txt.tag_configure("suspicious", foreground=COLOR_SUSPICIOUS)
        txt.tag_configure("dangerous", foreground=COLOR_DANGEROUS)
        txt.tag_configure("muted", foreground=TEXT_MUTED)
        txt.tag_configure("bold", font=FONT_BOLD)
        txt.tag_configure("rule_crit", foreground=COLOR_DANGEROUS)
        txt.tag_configure("rule_high", foreground=COLOR_SUSPICIOUS)
        txt.tag_configure("rule_med", foreground="#e3b341")
        txt.tag_configure("rule_low", foreground=ACCENT_CYAN)
        return txt

    def _build_footer(self):
        foot = tk.Frame(self, bg=BG_CARD2, pady=6)
        foot.pack(fill="x", side="bottom")
        tk.Label(foot,
                 text="⚠ SafeExec is an educational AI-based risk analyzer — NOT a replacement for antivirus software.",
                 font=FONT_SMALL, bg=BG_CARD2, fg=TEXT_MUTED).pack()

    def _add_border(self, widget):
        widget.configure(highlightbackground=BORDER, highlightthickness=1)

    # ─── LOGIC ────────────────────────────────────────────────────

    def _preload_model(self):
        def load():
            self._update_status("Loading AI model...", 5)
            scanner.preload_model()
            self._update_status("AI model ready.", 0)
        threading.Thread(target=load, daemon=True).start()

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file to analyze")
        if path:
            self.selected_file = path
            self.lbl_filepath.config(text=path, fg=TEXT_PRIMARY)
            try:
                size_kb = os.path.getsize(path) / 1024
                self.lbl_filesize.config(text=f"{size_kb:.1f} KB")
            except Exception:
                self.lbl_filesize.config(text="")
            self.btn_scan.config(state="normal")
            self._update_status("File selected. Click Analyze.", 0)

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.btn_scan.config(state="disabled", text="Analyzing...")
        self.btn_browse.config(state="disabled")
        self._clear_results()
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            result = scanner.scan_file(
                self.selected_file,
                progress_callback=lambda step, pct: self.after(0, self._update_status, step, pct)
            )
            self.after(0, self._display_results, result)
        except Exception as e:
            self.after(0, self._show_error, str(e))
        finally:
            self._scanning = False
            self.after(0, lambda: self.btn_scan.config(state="normal", text="🔍  Analyze"))
            self.after(0, lambda: self.btn_browse.config(state="normal"))

    def _update_status(self, msg: str, pct: int):
        self.lbl_status.config(text=msg)
        self.progressbar["value"] = pct

    def _clear_results(self):
        for tab in [self.tab_summary, self.tab_ai, self.tab_rules,
                    self.tab_ti, self.tab_behavior, self.tab_recommend]:
            self._set_text(tab, "")
        self.lbl_verdict.config(text="—", fg=TEXT_MUTED)
        self.lbl_verdict_desc.config(text="Scanning...")
        self._draw_meter(0, "—")
        self.lbl_score_num.config(text="Score: —")
        self.lbl_confidence.config(text="—")
        self.lbl_scantime.config(text="—")
        for v in self.meta_rows.values():
            v.config(text="—")

    def _display_results(self, result: dict):
        fusion  = result['fusion_result']
        ai      = result['ai_result']
        rules   = result['rule_result']
        ti      = result['ti_result']
        feats   = result['features']
        expl    = result['explanation']

        label   = fusion['final_label']
        score   = fusion['risk_score']
        conf    = fusion['confidence']
        color   = LABEL_COLORS.get(label, TEXT_MUTED)

        # Verdict card
        self.lbl_verdict.config(text=label, fg=color)
        self.lbl_verdict_desc.config(text=f"Risk Score: {score:.0f}/100  •  Model: {ai['model_type']}")
        self._draw_meter(score, label)
        self.lbl_score_num.config(text=f"Score: {score:.1f} / 100", fg=color)
        self.lbl_confidence.config(text=f"{conf:.1f}%")
        self.lbl_scantime.config(text=f"{result['scan_time_seconds']}s")

        # Metadata
        md5_val = feats.get('hash_md5') or '—'
        self.meta_rows['filename'].config(text=feats.get('filename', '—'))
        self.meta_rows['extension'].config(text=feats.get('extension', '—'))
        self.meta_rows['file_type_category'].config(text=feats.get('file_type_category', '—').capitalize())
        self.meta_rows['file_size_kb'].config(text=f"{feats.get('file_size_kb', 0)} KB")
        self.meta_rows['hash_md5'].config(text=md5_val[:18] + "..." if md5_val and len(md5_val) > 18 else md5_val)
        self.meta_rows['entropy'].config(text=str(feats.get('entropy', '—')))
        self.meta_rows['file_modified_human'].config(text=feats.get('file_modified_human', '—'))

        # Tabs
        self._populate_summary(expl, fusion, ai, rules, ti)
        self._populate_ai(ai, feats, expl)
        self._populate_rules(rules)
        self._populate_ti(ti)
        self._populate_behavior(fusion)
        self._populate_recommendations(expl)

    def _populate_summary(self, expl, fusion, ai, rules, ti):
        t = self.tab_summary
        label = fusion['final_label']
        tag = label.lower()
        bd = fusion['breakdown']

        lines = [
            ("ANALYSIS SUMMARY\n\n", "heading"),
            (expl['summary'] + "\n\n", None),
            ("ENGINE CONTRIBUTIONS\n", "heading"),
            (f"  AI Engine     : {ai['label']} ({ai['confidence']:.1f}% conf)  ✦ weight {int(bd['ai_weight']*100)}%  → {bd['ai_contribution']:.1f} pts\n", None),
            (f"  Heuristics    : {rules['heuristic_label']} ({rules['heuristic_score']:.0f}/100)  ✦ weight {int(bd['rule_weight']*100)}%  → {bd['rule_contribution']:.1f} pts\n", None),
            (f"  Threat Intel  : {ti['ti_label']} ({ti['ti_score']:.0f}/100)  ✦ weight {int(bd['ti_weight']*100)}%  → {bd['ti_contribution']:.1f} pts\n\n", None),
            ("THREAT SCENARIO\n", "heading"),
            (expl['threat_scenario'] + "\n", None),
        ]
        self._write_lines(t, lines)

    def _populate_ai(self, ai, feats, expl):
        t = self.tab_ai
        lines = [
            ("AI PREDICTION ENGINE\n\n", "heading"),
            (f"Model Type  : {ai['model_type']}\n", None),
            (f"Prediction  : {ai['label']}\n", ai['label'].lower()),
            (f"Confidence  : {ai['confidence']:.1f}%\n\n", None),
            ("PROBABILITY DISTRIBUTION\n", "heading"),
            (f"  Safe       : {ai['prob_safe']:.1f}%\n", "safe"),
            (f"  Suspicious : {ai['prob_suspicious']:.1f}%\n", "suspicious"),
            (f"  Dangerous  : {ai['prob_dangerous']:.1f}%\n\n", "dangerous"),
            ("EXPLANATION\n", "heading"),
            (expl['ai_explanation'] + "\n\n", None),
        ]
        top_feats = expl.get('top_contributing_features', [])
        if top_feats:
            lines.append(("TOP CONTRIBUTING FEATURES\n", "heading"))
            for f in top_feats:
                lines.append((f"  {f['feature']:35s} val={f['value']:.3f}  imp={f['importance']:.4f}\n", None))
        self._write_lines(t, lines)

    def _populate_rules(self, rules):
        t = self.tab_rules
        triggered = rules.get('triggered_rules', [])
        lines = [
            ("RULE-BASED HEURISTIC ENGINE\n\n", "heading"),
            (f"Heuristic Score : {rules['heuristic_score']:.0f} / 100\n", None),
            (f"Label           : {rules['heuristic_label']}\n", rules['heuristic_label'].lower()),
            (f"Rules Triggered : {rules['rule_count']}\n\n", None),
            ("TRIGGERED RULES\n", "heading"),
        ]
        for rule in triggered:
            sev = rule.get('severity', 'INFO')
            tag = {'CRITICAL': 'rule_crit', 'HIGH': 'rule_high',
                   'MEDIUM': 'rule_med', 'LOW': 'rule_low'}.get(sev, 'muted')
            lines.append((f"\n  [{sev}] {rule['rule']}\n", tag))
            lines.append((f"  {rule['detail']}\n", None))
            if rule.get('score_added', 0) > 0:
                lines.append((f"  Score added: +{rule['score_added']}\n", "muted"))
        self._write_lines(t, lines)

    def _populate_ti(self, ti):
        t = self.tab_ti
        matches = ti.get('ti_matches', [])
        lines = [
            ("THREAT INTELLIGENCE ENGINE\n\n", "heading"),
            (f"TI Score    : {ti['ti_score']:.0f} / 100\n", None),
            (f"Label       : {ti['ti_label']}\n", ti['ti_label'].lower()),
            (f"Hash Match  : {'YES ⚠' if ti['hash_matched'] else 'No'}\n\n", "dangerous" if ti['hash_matched'] else None),
            ("DATABASE MATCHES\n", "heading"),
        ]
        for m in matches:
            sev = m.get('severity', 'INFO')
            tag = {'CRITICAL': 'rule_crit', 'HIGH': 'rule_high',
                   'MEDIUM': 'rule_med', 'LOW': 'rule_low'}.get(sev, 'muted')
            lines.append((f"\n  [{sev}] {m['type']}\n", tag))
            lines.append((f"  {m['detail']}\n", None))
        self._write_lines(t, lines)

    def _populate_behavior(self, fusion):
        t = self.tab_behavior
        signals = fusion.get('user_behavior_signals', [])
        lines = [
            ("USER BEHAVIOR AWARENESS LAYER\n\n", "heading"),
            ("This layer provides context-aware security advice based on file characteristics\n"
             "and common malware distribution behaviors.\n\n", "muted"),
        ]
        for sig in signals:
            lv = sig.get('level', 'INFO')
            tag = {'HIGH': 'rule_high', 'MEDIUM': 'rule_med', 'LOW': 'rule_low'}.get(lv, 'muted')
            lines.append((f"[{lv}] {sig['signal']}\n", tag))
            lines.append((f"  {sig['advice']}\n\n", None))
        self._write_lines(t, lines)

    def _populate_recommendations(self, expl):
        t = self.tab_recommend
        recs = expl.get('recommendations', [])
        lines = [
            ("RECOMMENDED ACTIONS\n\n", "heading"),
        ]
        for rec in recs:
            lines.append((rec + "\n", None))
        self._write_lines(t, lines)

    def _write_lines(self, widget, lines: list):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        for text, tag in lines:
            if tag:
                widget.insert("end", text, tag)
            else:
                widget.insert("end", text)
        widget.config(state="disabled")

    def _set_text(self, widget, text: str):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.config(state="disabled")

    def _show_error(self, msg: str):
        self._set_text(self.tab_summary, f"ERROR during scan:\n\n{msg}")
        self.lbl_verdict.config(text="Error", fg=COLOR_DANGEROUS)
        self._update_status("Scan failed.", 0)


def main():
    app = SafeExecApp()
    app.mainloop()


if __name__ == "__main__":
    main()
