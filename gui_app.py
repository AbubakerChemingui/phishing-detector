"""
gui_app.py - Desktop GUI for Phishing Email Detection
Red‑and‑black analyst console theme, split‑pane layout, keyboard shortcuts.
Supports language switching (English, French, Arabic).
Keeps all ML logic, model loading, cleaning, and the --test flag unchanged.
"""

import os
import sys
# Set the working directory to the script's directory so that relative paths in
# imported modules (if any) resolve correctly.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Import core logic
from core import (
    clean_email_text,
    apply_hardening,
    strip_html,
    load_artifacts,
    MODEL,
    VECTORIZER,
    FEATURE_NAMES,
    FEATURE_IMPORTANCES,
    get_alert,
    get_risk_color,
    analyze_email
)

import re
import unicodedata
import datetime
from email import message_from_string
from email.policy import default as default_policy

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# 4. Tooltip Helper (robust for any widget)
# ---------------------------------------------------------------------------

class ToolTip:
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        # Position near the widget (bottom‑left corner)
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 10

        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#2c3e50",
            foreground="#ffffff",
            relief=tk.SOLID,
            borderwidth=1,
            font=("Helvetica", 9),
            padx=6,
            pady=3
        )
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


# ---------------------------------------------------------------------------
# 5. Tkinter Desktop GUI – Red‑Black Analyst Console with Language Support
# ---------------------------------------------------------------------------

class PhishingDetectorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Phishing Email Detector")
        self.root.geometry("1000x600")
        self.root.minsize(800, 500)

        # Language state
        self.language = 'en'  # default language
        self.translations = {
            'en': {
                'title': "Phishing Email Detector",
                'input_label': "[INPUT]",
                'output_label': "[OUTPUT]",
                'open_file': "Open .eml/.txt",
                'check_email': "Check Email",
                'clear': "Clear",
                'batch_csv': "Batch CSV",
                'save_report': "Save Report",
                'placeholder_input': "Paste the full e-mail here...",
                'close': "Close",
                'open_file_tooltip': "Load and parse Subject & Body from a .eml or .txt file",
                'check_email_tooltip': "Run TF‑IDF classification and explainability analysis",
                'clear_tooltip': "Clear text input and reset results",
                'batch_csv_tooltip': "Analyze an entire CSV dataset in a separate window",
                'save_report_tooltip': "Export current analysis and top contributing words to .txt",
                'hardening_label': "Enable Hardening (NFKC normalisation, homoglyphs, leet‑speak, zero‑width stripping)",
                'hardening_tooltip': "Pre‑sanitize text against evasion techniques before vectorization",
                'medium_threshold': "Medium Threshold:",
                'high_threshold': "High Threshold:",
                'options_label': " Options & Thresholds ",
                'analysis_result_label': " Analysis Result ",
                'prediction_label': "Prediction:",
                'confidence_label': "Confidence:",
                'alert_label': "Alert Tier:",
                'top_words_label': "Top contributing words:",
                'none': "None",
                'status_ready': "Ready",
                'status_reading': "Reading {}...",
                'status_loaded': "Loaded {}",
                'status_analyzing': "Analyzing e-mail...",
                'status_analysis_complete': "Analysis complete",
                'status_analysis_failed': "Analysis failed",
                'status_cleared': "Cleared input and results",
                'status_saving': "Saving report...",
                'status_report_saved': "Report saved: {}",
                'status_batch_processing': "Processing Batch CSV...",
                'status_batch_finished': "Batch processing finished",
                'error_file': "File Error",
                'error_analysis': "Analysis Error",
                'error_save': "Save Error",
                'error_batch_csv': "Batch CSV Error",
                'warning_batch_empty': "Batch CSV",
                'warning_batch_empty_msg': "The selected CSV file is empty.",
                'info_save_report': "Save Report",
                'info_save_report_msg': "Please check an email before saving a report.",
                'info_report_saved': "Report Saved",
                'info_report_saved_msg': "Report successfully saved to:\n{}",
                'info_export_success': "Export Successful",
                'info_export_success_msg': "Saved {} rows to:\n{}",
                'error_export_failed': "Export Failed",
                'error_export_failed_msg': "Could not save file:\n{}",
                'batch_window_title': "Batch Analysis Results - {}",
                'batch_label': "Analyzed {} records from {}",
                'export_button': "Export Results (CSV)",
                'cheat_sheet_title': "Cheat Sheet",
                'cheat_sheet_lines': [
                    "Keyboard Shortcuts",
                    "---------------",
                    "Alt+D   : Toggle theme (black / dark gray)",
                    "Alt+A   : Cycle accent colour",
                    "1‑5     : Select accent colour directly",
                    "F1 / ?  : Show this cheat sheet",
                    "Esc     : Blur focus (return to root)",
                    "Ctrl+Enter : Analyse e‑mail",
                    "",
                    "Tip: Use Enter in the input box for quick analyse as well."
                ],
                'language_label': "Language:",
                'language_tooltip': "Select interface language",
            },
            'fr': {
                'title': "Détecteur d'emails de phishing",
                'input_label': "[ENTRÉE]",
                'output_label': "[SORTIE]",
                'open_file': "Ouvrir .eml/.txt",
                'check_email': "Vérifier l'email",
                'clear': "Effacer",
                'batch_csv': "CSV par lot",
                'save_report': "Sauvegarder le rapport",
                'placeholder_input': "Collez le courriel complet ici...",
                'close': "Fermer",
                'open_file_tooltip': "Charger et analyser le sujet et le corps d'un fichier .eml ou .txt",
                'check_email_tooltip': "Exécuter l'analyse de classification TF‑IDF et l'explicabilité",
                'clear_tooltip': "Effacer l'entrée de texte et réinitialiser les résultats",
                'batch_csv_tooltip': "Analyser un ensemble de données CSV dans une fenêtre séparée",
                'save_report_tooltip': "Exporter l'analyse actuelle et les mots contributeurs vers .txt",
                'hardening_label': "Activer le renforcement (normalisation NFKC, remplacement des homoglyphes, décodage leet‑speak, suppression des caractères zéro‑largeur)",
                'hardening_tooltip': "Pré‑nettoyer le texte contre les techniques d'évasion avant la vectorisation",
                'medium_threshold': "Seuil moyen :",
                'high_threshold': "Seuil élevé :",
                'options_label': " Options & Seuils ",
                'analysis_result_label': " Résultat de l'analyse ",
                'prediction_label': "Prédiction :",
                'confidence_label': "Confiance :",
                'alert_label': "Niveau d'alerte :",
                'top_words_label': "Mots contributeurs principaux :",
                'none': "Aucun",
                'status_ready': "Prêt",
                'status_reading': "Lecture de {}...",
                'status_loaded': "Chargé {}",
                'status_analyzing': "Analyse de l'email...",
                'status_analysis_complete': "Analyse terminée",
                'status_analysis_failed': "Échec de l'analyse",
                'status_cleared': "Entrée et résultats effacés",
                'status_saving': "Sauvegarde du rapport...",
                'status_report_saved': "Rapport sauvegardé : {}",
                'status_batch_processing': "Traitement du CSV par lot...",
                'status_batch_finished': "Traitement par lot terminé",
                'error_file': "Erreur de fichier",
                'error_analysis': "Erreur d'analyse",
                'error_save': "Erreur de sauvegarde",
                'error_batch_csv': "Erreur CSV par lot",
                'warning_batch_empty': "CSV par lot",
                'warning_batch_empty_msg': "Le fichier CSV sélectionné est vide.",
                'info_save_report': "Sauvegarder le rapport",
                'info_save_report_msg': "Veuillez vérifier un email avant de sauvegarder un rapport.",
                'info_report_saved': "Rapport sauvegardé",
                'info_report_saved_msg': "Rapport sauvegardé avec succès vers :\n{}",
                'info_export_success': "Export réussi",
                'info_export_success_msg': "Exporté {} lignes vers :\n{}",
                'error_export_failed': "Échec de l'export",
                'error_export_failed_msg': "Impossible de sauvegarder le fichier :\n{}",
                'batch_window_title': "Résultats de l'analyse par lot - {}",
                'batch_label': "Analyse de {} enregistrements provenant de {}",
                'export_button': "Exporter les résultats (CSV)",
                'cheat_sheet_title': "Feuille de triche",
                'cheat_sheet_lines': [
                    "Raccourcis clavier",
                    "----------------",
                    "Alt+D   : Basculer le thème (noir / gris foncé)",
                    "Alt+A   : Changer la couleur d'accent",
                    "1‑5     : Sélectionner directement la couleur d'accent",
                    "F1 / ?  : Afficher cette feuille de triche",
                    "Esc     : Réinitialiser le focus (retour à la fenêtre principale)",
                    "Ctrl+Entrée : Analyser l'email",
                    "",
                    "Astuce : Utilisez Entrée dans la zone de saisie pour une analyse rapide."
                ],
                'language_label': "Langue :",
                'language_tooltip': "Sélectionner la langue de l'interface",
            },
'ar': {
                'title': "كاشف رسائل التصيد",
                'input_label': "[الإدخال]",
                'output_label': "[الإخراج]",
                'open_file': "فتح .eml/.txt",
                'check_email': "التحقق من البريد",
                'clear': "مسح",
                'batch_csv': "معالجة CSV بالدفعة",
                'save_report': "حفظ التقرير",
                'placeholder_input': "الصق البريد الإلكتروني الكامل هنا...",
                'close': "إغلاق",
                'open_file_tooltip': "تحميل وتحليل الموضوع والجسم من ملف .eml أو .txt",
                'check_email_tooltip': "تشغيل تحليل تصنيف TF‑IDF والتفسير",
                'clear_tooltip': "مسح إدخال النص وإعادة تعيين النتائج",
                'batch_csv_tooltip': "تحليل مجموعة بيانات CSV في نافذة منفصلة",
                'save_report_tooltip': "تصدير التحليل الحالي والكلمات المساهمة إلى .txt",
                'hardening_label': "تفعيل التقوية (التطبيع NFKC، استبدال الأحرف المتشابهة، فك ترميز leet‑speak، إزالة الأحرف ذات العرض الصفر)",
                'hardening_tooltip': "تنظيف النص مسبقًا ضد تقنيات التهرب قبل المتجهنة",
                'medium_threshold': "العتبة المتوسطة:",
                'high_threshold': "العتبة العالية:",
                'options_label': "الخيارات والعتبات",
                'analysis_result_label': "نتيجة التحليل",
                'prediction_label': "التنبؤ:",
                'confidence_label': "الثقة:",
                'alert_label': "مستوى التنبيه:",
                'top_words_label': "أهم الكلمات المساهمة:",
                'none': "لا شيء",
                'status_ready': "جاهز",
                'status_reading': "جاري قراءة {}...",
                'status_loaded': "تم تحميل {}",
                'status_analyzing': "جاري تحليل البريد...",
                'status_analysis_complete': "اكتمل التحليل",
                'status_analysis_failed': "فشل التحليل",
                'status_cleared': "تم مسح الإدخال والنتائج",
                'status_saving': "جاري حفظ التقرير...",
                'status_report_saved': "تم حفظ التقرير: {}",
                'status_batch_processing': "جاري معالجة CSV بالدفعة...",
                'status_batch_finished': "انتهت معالجة الدفعة",
                'error_file': "خطأ في الملف",
                'error_analysis': "خطأ في التحليل",
                'error_save': "خطأ في الحفظ",
                'error_batch_csv': "خطأ في CSV بالدفعة",
                'warning_batch_empty': "CSV بالدفعة",
                'warning_batch_empty_msg': "ملف CSV المحدد فارغ.",
                'info_save_report': "حفظ التقرير",
                'info_save_report_msg': "يرجى التحقق من بريد إلكتروني قبل حفظ التقرير.",
                'info_report_saved': "تم حفظ التقرير",
                'info_report_saved_msg': "تم حفظ التقرير بنجاح إلى:\n{}",
                'info_export_success': "نجاح التصدير",
                'info_export_success_msg': "تم تصدير {} سجلات إلى:\n{}",
                'error_export_failed': "فشل التصدير",
                'error_export_failed_msg': "تعذر حفظ الملف:\n{}",
                'batch_window_title': "نتائج التحليل بالدفعة - {}",
                'batch_label': "تم تحليل {} سجلات من {}",
                'export_button': "تصدير النتائج (CSV)",
                'cheat_sheet_title': "ورقة الغش",
                'cheat_sheet_lines': [
                    "اختصارات لوحة المفاتيح",
                    "-------------------",
                    "Alt+D   : تبديل السمة (أسود / رمادي داكن)",
                    "Alt+A   : دورة لون التمييز",
                    "1‑5     : تحديد لون التمييز مباشرة",
                    "F1 / ?  : عرض ورقة الغش",
                    "Esc     : إبطال التركيز (العودة إلى الجذر)",
                    "Ctrl+Enter : تحليل البريد",
                    "",
                    "نصيحة: استخدم Enter في مربع الإدخال للتحليل السريع."
                ],
                'language_label': "اللغة:",
                'language_tooltip': "اختر لغة الواجهة",
            }
        }

        # Theme state
        self.dark_theme = True          # True = black background, False = dark gray (optional toggle)
        self.accent_index = 0           # 0‑4 selects from ACCENT_COLORS
        self.ACCENT_COLORS = [
            "#ff0000",  # vivid red
            "#ff3333",
            "#ff6666",
            "#ff9999",
            "#ffcccc"
        ]
        self.BG_COLOR = "#000000" if self.dark_theme else "#2b2b2b"
        self.FG_COLOR = self.ACCENT_COLORS[self.accent_index]

        self.last_analysis = None

        # Store widget references for language updates
        self.widgets = {}

        self._build_ui()
        self._apply_theme()
        self._bind_shortcuts()
        self.set_status(self.tr('status_ready'))

    def tr(self, key):
        """Return translated string for current language."""
        return self.translations[self.language].get(key, key)

    def update_language(self):
        """Update all translatable widgets."""
        # Update window title
        self.root.title(self.tr('title'))

        # Update labels and buttons
        if 'lbl_input' in self.widgets:
            self.widgets['lbl_input'].config(text=self.tr('input_label'))
        if 'lbl_output' in self.widgets:
            self.widgets['lbl_output'].config(text=self.tr('output_label'))
        if 'btn_open' in self.widgets:
            self.widgets['btn_open'].config(text=self.tr('open_file'))
            self.widgets['btn_open'].tooltip_text = self.tr('open_file_tooltip')
        if 'btn_check' in self.widgets:
            self.widgets['btn_check'].config(text=self.tr('check_email'))
            self.widgets['btn_check'].tooltip_text = self.tr('check_email_tooltip')
        if 'btn_clear' in self.widgets:
            self.widgets['btn_clear'].config(text=self.tr('clear'))
            self.widgets['btn_clear'].tooltip_text = self.tr('clear_tooltip')
        if 'btn_batch' in self.widgets:
            self.widgets['btn_batch'].config(text=self.tr('batch_csv'))
            self.widgets['btn_batch'].tooltip_text = self.tr('batch_csv_tooltip')
        if 'btn_report' in self.widgets:
            self.widgets['btn_report'].config(text=self.tr('save_report'))
            self.widgets['btn_report'].tooltip_text = self.tr('save_report_tooltip')
        if 'chk_harden' in self.widgets:
            self.widgets['chk_harden'].config(text=self.tr('hardening_label'))
            self.widgets['chk_harden'].tooltip_text = self.tr('hardening_tooltip')
        if 'lbl_medium' in self.widgets:
            self.widgets['lbl_medium'].config(text=self.tr('medium_threshold'))
        if 'lbl_high' in self.widgets:
            self.widgets['lbl_high'].config(text=self.tr('high_threshold'))
        if 'lbl_options' in self.widgets:
            self.widgets['lbl_options'].config(text=self.tr('options_label'))
        if 'lbl_res_frame' in self.widgets:
            self.widgets['lbl_res_frame'].config(text=self.tr('analysis_result_label'))
        if 'lbl_pred_label' in self.widgets:
            self.widgets['lbl_pred_label'].config(text=self.tr('prediction_label'))
        if 'lbl_conf_label' in self.widgets:
            self.widgets['lbl_conf_label'].config(text=self.tr('confidence_label'))
        if 'lbl_alert_label' in self.widgets:
            self.widgets['lbl_alert_label'].config(text=self.tr('alert_label'))
        if 'lbl_words_label' in self.widgets:
            self.widgets['lbl_words_label'].config(text=self.tr('top_words_label'))
        if 'lbl_words' in self.widgets and self.lbl_words["text"] != self.tr('none'):
            # Only update if not showing actual words (to avoid overwriting)
            pass
        if 'language_label' in self.widgets:
            self.widgets['language_label'].config(text=self.tr('language_label'))
        if 'language_combo' in self.widgets:
            # Update combobox displayed value (keep current selection)
            pass
        if 'status_bar' in self.widgets:
            # Status bar text will be updated via set_status as needed
            pass
        # Update cheat sheet if open? We'll handle when opening.

        # Update tooltips (store them separately)
        self._update_tooltips()

    def _update_tooltips(self):
        """Update tooltip texts for widgets that have them."""
        # We'll store tooltip text in a custom attribute for simplicity
        pass

    # -----------------------------------------------------------------------
    # UI Construction
    # -----------------------------------------------------------------------
    def _build_ui(self):
        # Main paned window (split‑pane)
        self.paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ----- Left Pane: Input & Controls -----
        left_frame = ttk.Frame(self.paned)
        self.paned.add(left_frame, weight=1)

        # [INPUT] label
        lbl_input = ttk.Label(left_frame, text=self.tr('input_label'), font=("Helvetica", 10, "bold"))
        lbl_input.pack(anchor="w", pady=(0, 4))
        self.widgets['lbl_input'] = lbl_input

        self.text_input = ScrolledText(
            left_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            height=12
        )
        self.text_input.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.text_input.insert("1.0", self.tr('placeholder_input'))
        self.text_input.bind("<FocusIn>", self._on_text_focus_in)

        # Button bar under input
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 8))

        btn_open = ttk.Button(btn_frame, text=self.tr('open_file'), command=self.action_open_file)
        btn_open.pack(side=tk.LEFT, padx=(0, 4))
        btn_open.tooltip_text = self.tr('open_file_tooltip')
        ToolTip(btn_open, btn_open.tooltip_text)
        self.widgets['btn_open'] = btn_open

        btn_check = ttk.Button(btn_frame, text=self.tr('check_email'), command=self.action_check_email)
        btn_check.pack(side=tk.LEFT, padx=(0, 4))
        btn_check.tooltip_text = self.tr('check_email_tooltip')
        ToolTip(btn_check, btn_check.tooltip_text)
        self.widgets['btn_check'] = btn_check

        btn_clear = ttk.Button(btn_frame, text=self.tr('clear'), command=self.action_clear)
        btn_clear.pack(side=tk.LEFT, padx=(0, 4))
        btn_clear.tooltip_text = self.tr('clear_tooltip')
        ToolTip(btn_clear, btn_clear.tooltip_text)
        self.widgets['btn_clear'] = btn_clear

        btn_batch = ttk.Button(btn_frame, text=self.tr('batch_csv'), command=self.action_batch_csv)
        btn_batch.pack(side=tk.LEFT, padx=(0, 4))
        btn_batch.tooltip_text = self.tr('batch_csv_tooltip')
        ToolTip(btn_batch, btn_batch.tooltip_text)
        self.widgets['btn_batch'] = btn_batch

        btn_report = ttk.Button(btn_frame, text=self.tr('save_report'), command=self.action_save_report)
        btn_report.pack(side=tk.LEFT, padx=(0, 4))
        btn_report.tooltip_text = self.tr('save_report_tooltip')
        ToolTip(btn_report, btn_report.tooltip_text)
        self.widgets['btn_report'] = btn_report

        # ----- Right Pane: Output & Options -----
        right_frame = ttk.Frame(self.paned)
        self.paned.add(right_frame, weight=1)

        # [OUTPUT] label
        lbl_output = ttk.Label(right_frame, text=self.tr('output_label'), font=("Helvetica", 10, "bold"))
        lbl_output.pack(anchor="w", pady=(0, 4))
        self.widgets['lbl_output'] = lbl_output

        # Results frame
        res_frame = ttk.LabelFrame(right_frame, text=self.tr('analysis_result_label'), padding=10)
        res_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.widgets['lbl_res_frame'] = res_frame

        # Prediction row
        row1 = ttk.Frame(res_frame)
        row1.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(row1, text=self.tr('prediction_label'), font=("Helvetica", 10)).pack(side=tk.LEFT)
        self.widgets['lbl_pred_label'] = row1.winfo_children()[0]  # the label we just packed
        self.lbl_pred = tk.Label(row1, text="-", font=("Helvetica", 14, "bold"))
        self.lbl_pred.pack(side=tk.LEFT, padx=(10, 0))
        self.widgets['lbl_pred'] = self.lbl_pred

        # Confidence & Alert Tier row
        row2 = ttk.Frame(res_frame)
        row2.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(row2, text=self.tr('confidence_label'), font=("Helvetica", 10)).pack(side=tk.LEFT)
        self.widgets['lbl_conf_label'] = row2.winfo_children()[0]
        self.lbl_conf = tk.Label(row2, text="-", font=("Helvetica", 10, "bold"))
        self.lbl_conf.pack(side=tk.LEFT, padx=(8, 20))
        self.widgets['lbl_conf'] = self.lbl_conf

        ttk.Label(row2, text=self.tr('alert_label'), font=("Helvetica", 10)).pack(side=tk.LEFT)
        self.widgets['lbl_alert_label'] = row2.winfo_children()[2]
        self.lbl_alert = tk.Label(row2, text="-", font=("Helvetica", 10, "bold"))
        self.lbl_alert.pack(side=tk.LEFT, padx=(8, 0))
        self.widgets['lbl_alert'] = self.lbl_alert

        # Top words explainability
        row3 = ttk.Frame(res_frame)
        row3.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(row3, text=self.tr('top_words_label'), font=("Helvetica", 10)).pack(anchor="w")
        self.widgets['lbl_words_label'] = row3.winfo_children()[0]
        self.lbl_words = tk.Label(
            res_frame,
            text=self.tr('none'),
            font=("Consolas", 9),
            wraplength=720,
            justify=tk.LEFT
        )
        self.lbl_words.pack(anchor="w", pady=(2, 0))
        self.widgets['lbl_words'] = self.lbl_words

        # ----- Options Pane (under output) -----
        opts_frame = ttk.LabelFrame(right_frame, text=self.tr('options_label'), padding=10)
        opts_frame.pack(fill=tk.X, pady=(8, 0))
        self.widgets['lbl_options'] = opts_frame  # Actually the LabelFrame itself

        # Hardening checkbox
        chk_harden = ttk.Checkbutton(
            opts_frame,
            text=self.tr('hardening_label'),
            variable=tk.BooleanVar(value=False)
        )
        self.harden_var = tk.BooleanVar(value=False)
        chk_harden.configure(variable=self.harden_var)
        chk_harden.pack(anchor="w", pady=(0, 8))
        chk_harden.tooltip_text = self.tr('hardening_tooltip')
        ToolTip(chk_harden, chk_harden.tooltip_text)
        self.widgets['chk_harden'] = chk_harden

        # Sliders layout
        slider_grid = ttk.Frame(opts_frame)
        slider_grid.pack(fill=tk.X)

        # Keep real references: widget["variable"] only returns the Tcl
        # variable NAME string, not the object (that was the crash bug).
        self.med_thresh_var = tk.DoubleVar(value=0.65)
        self.high_thresh_var = tk.DoubleVar(value=0.85)

        # Medium threshold slider
        ttk.Label(slider_grid, text=self.tr('medium_threshold'), font=("Helvetica", 10)).grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        self.widgets['lbl_medium'] = slider_grid.winfo_children()[0]
        self.scale_med = ttk.Scale(
            slider_grid,
            from_=0.0,
            to=1.0,
            variable=self.med_thresh_var,
            command=self._on_threshold_change
        )
        self.scale_med.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=3)
        self.lbl_med_val = ttk.Label(slider_grid, text="0.65", width=6, font=("Helvetica", 10, "bold"))
        self.lbl_med_val.grid(row=0, column=2, sticky="w", pady=3)
        self.widgets['lbl_med_val'] = self.lbl_med_val

        # High threshold slider
        ttk.Label(slider_grid, text=self.tr('high_threshold'), font=("Helvetica", 10)).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        self.widgets['lbl_high'] = slider_grid.winfo_children()[3]  # after previous row widgets
        self.scale_high = ttk.Scale(
            slider_grid,
            from_=0.0,
            to=1.0,
            variable=self.high_thresh_var,
            command=self._on_threshold_change
        )
        self.scale_high.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=3)
        self.lbl_high_val = ttk.Label(slider_grid, text="0.85", width=6, font=("Helvetica", 10, "bold"))
        self.lbl_high_val.grid(row=1, column=2, sticky="w", pady=3)
        self.widgets['lbl_high_val'] = self.lbl_high_val

        slider_grid.columnconfigure(1, weight=1)

        # (med_thresh_var / high_thresh_var already hold the live DoubleVar
        # objects created above - do NOT reassign from widget["variable"].)

        # Language selector
        lang_frame = ttk.Frame(opts_frame)
        lang_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(lang_frame, text=self.tr('language_label'), font=("Helvetica", 10)).pack(side=tk.LEFT, padx=(0, 8))
        self.widgets['language_label'] = lang_frame.winfo_children()[0]
        self.language_var = tk.StringVar(value=self.language)
        language_combo = ttk.Combobox(
            lang_frame,
            textvariable=self.language_var,
            values=['en', 'fr', 'ar'],
            state='readonly',
            width=5
        )
        language_combo.pack(side=tk.LEFT)
        self.widgets['language_combo'] = language_combo
        language_combo.bind('<<ComboboxSelected>>', self._on_language_change)
        language_combo.tooltip_text = self.tr('language_tooltip')
        ToolTip(language_combo, language_combo.tooltip_text)

        # Status Bar
        self.status_bar = ttk.Label(
            self.root,
            text=self.tr('status_ready'),
            relief=tk.SUNKEN,
            anchor="w",
            font=("Helvetica", 9),
            padding=(8, 4)
        )
        self.widgets['status_bar'] = self.status_bar
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Set placeholder text
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert("1.0", self.tr('placeholder_input'))

    def _on_language_change(self, event):
        new_lang = self.language_var.get()
        if new_lang != self.language:
            self.language = new_lang
            self.update_language()
            # Also update placeholder text
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", self.tr('placeholder_input'))

    # -----------------------------------------------------------------------
    # Theme & Accent Handling
    # -----------------------------------------------------------------------
    def _apply_theme(self):
        bg = self.BG_COLOR
        fg = self.FG_COLOR
        self.root.configure(bg=bg)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        # Configure ttk widgets
        style.configure(".", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background=bg, foreground=fg)
        style.configure("TCheckbutton", background=bg, foreground=fg)
        style.configure("TRadiobutton", background=bg, foreground=fg)
        style.configure("TScale", background=bg)
        style.configure("TEntry", fieldbackground=bg, foreground=fg)
        style.configure("TCombobox", fieldbackground=bg, foreground=fg)
        style.configure("Horizontal.TScale", troughcolor=bg, background=fg)
        # Frames and LabelFrames get background via style
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        # Update specific widget colors
        # (value labels are tk.Label: they need explicit foreground, otherwise
        # text renders in default black on the black background = invisible)
        self.lbl_pred.configure(background=bg)
        self.lbl_conf.configure(background=bg, foreground=fg)
        self.lbl_alert.configure(background=bg)
        self.lbl_words.configure(background=bg, foreground=fg)
        self.text_input.configure(background=bg, foreground=fg, insertbackground=fg)
        # Update button bar colors (they inherit from style)
        # Ensure status bar uses same colors
        self.status_bar.configure(background=bg, foreground=fg)

    def _bind_shortcuts(self):
        self.root.bind("<Alt-d>", lambda e: self._toggle_theme())
        self.root.bind("<Alt-a>", lambda e: self._cycle_accent())
        for i in range(1, 6):
            self.root.bind(f"<Key-{i}>", lambda e, idx=i-1: self._set_accent(idx))
        self.root.bind("<F1>", lambda e: self._show_cheat_sheet())
        self.root.bind("<Key-/>", lambda e: self._show_cheat_sheet())  #/? for cheat sheet
        self.root.bind("<Escape>", lambda e: self.root.focus_set())
        self.root.bind("<Control-Return>", lambda e: self.action_check_email())

    def _toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self.BG_COLOR = "#000000" if self.dark_theme else "#2b2b2b"
        self._apply_theme()

    def _cycle_accent(self):
        self.accent_index = (self.accent_index + 1) % len(self.ACCENT_COLORS)
        self.FG_COLOR = self.ACCENT_COLORS[self.accent_index]
        self._apply_theme()

    def _set_accent(self, idx):
        if 0 <= idx < len(self.ACCENT_COLORS):
            self.accent_index = idx
            self.FG_COLOR = self.ACCENT_COLORS[self.accent_index]
            self._apply_theme()

    def _show_cheat_sheet(self):
        # Create a modal top‑level window
        cheat = tk.Toplevel(self.root)
        cheat.title(self.tr('cheat_sheet_title'))
        cheat.transient(self.root)
        cheat.grab_set()
        cheat.geometry("340x260")
        cheat.resizable(False, False)
        # Content
        frm = ttk.Frame(cheat, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        lines = self.tr('cheat_sheet_lines')
        for i, line in enumerate(lines):
            ttk.Label(frm, text=line, font=("Consolas", 9)).grid(row=i, column=0, sticky="w", pady=2)
        # Close button
        btn_close = ttk.Button(frm, text=self.tr('close'), command=cheat.destroy)
        btn_close.grid(row=len(lines), column=0, pady=(10, 0), sticky="e")
        cheat.wait_window()

    # -----------------------------------------------------------------------
    # Helper & Event Handlers
    # -----------------------------------------------------------------------
    def set_status(self, text: str):
        self.status_bar.config(text=text)
        self.root.update_idletasks()

    def _on_text_focus_in(self, event):
        current_text = self.text_input.get("1.0", tk.END).strip()
        if current_text == self.tr('placeholder_input'):
            self.text_input.delete("1.0", tk.END)

    def _on_enter_pressed(self, event):
        # Trigger check email on Enter key
        self.action_check_email()
        return "break"

    def _on_threshold_change(self, val):
        med = self.med_thresh_var.get()
        high = self.high_thresh_var.get()
        self.lbl_med_val.config(text=f"{med:.2f}")
        self.lbl_high_val.config(text=f"{high:.2f}")

        # If an email is already displayed and analyzed, update the alert label dynamically
        if self.last_analysis and self.last_analysis.get("prediction") in ("Phishing", "Legitimate"):
            conf = self.last_analysis["confidence"]
            pred = self.last_analysis["prediction"]
            alert = get_alert(pred, conf, med, high)
            color = get_risk_color(pred, conf, med, high)
            self.lbl_alert.config(text=alert, fg=color)
            self.lbl_pred.config(fg=color)

    # -----------------------------------------------------------------------
    # Actions (unchanged ML logic)
    # -----------------------------------------------------------------------
    def action_open_file(self):
        file_path = filedialog.askopenfilename(
            title=self.tr('open_file'),
            filetypes=[("Email and Text Files", "*.eml *.txt"), ("EML Files", "*.eml"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        self.set_status(self.tr('status_reading').format(os.path.basename(file_path)))
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            extracted_body = ""
            extracted_subject = ""

            if file_path.lower().endswith(".eml"):
                msg = message_from_string(content, policy=default_policy)
                extracted_subject = msg.get("subject", "")

                if msg.is_multipart():
                    html_part = ""
                    plain_part = ""
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdisp = str(part.get("content-disposition", ""))
                        if "attachment" in cdisp:
                            continue
                        if ctype == "text/plain" and not plain_part:
                            plain_part = part.get_content()
                        elif ctype == "text/html" and not html_part:
                            html_part = part.get_content()

                    if plain_part:
                        extracted_body = plain_part
                    elif html_part:
                        extracted_body = strip_html(html_part)
                else:
                    ctype = msg.get_content_type()
                    payload = msg.get_content()
                    if ctype == "text/html":
                        extracted_body = strip_html(payload)
                    else:
                        extracted_body = payload

                final_text = f"Subject: {extracted_subject}\n\n{extracted_body}".strip()
            else:
                final_text = content

            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", final_text)
            self.set_status(self.tr('status_loaded').format(os.path.basename(file_path)))
        except Exception as ex:
            messagebox.showerror(self.tr('error_file'), f"Failed to read file:\n{str(ex)}")
            self.set_status(self.tr('status_analysis_failed'))

    def action_check_email(self):
        raw_text = self.text_input.get("1.0", tk.END).strip()
        if raw_text == self.tr('placeholder_input'):
            raw_text = ""

        med_thresh = self.med_thresh_var.get()
        high_thresh = self.high_thresh_var.get()
        harden = self.harden_var.get()

        self.set_status(self.tr('status_analyzing'))
        try:
            res = analyze_email(raw_text, med_thresh, high_thresh, harden_first=harden)
            self.last_analysis = res
            self.last_analysis["raw_input"] = raw_text

            self.lbl_pred.config(text=res["prediction"], fg=res["color"])
            self.lbl_conf.config(text=res["confidence_str"])
            self.lbl_alert.config(text=res["alert"], fg=res["color"])

            if res["top_words"]:
                words_str = ", ".join(f"{w} ({score:.5f})" for w, score in res["top_words"])
                self.lbl_words.config(text=words_str)
            else:
                self.lbl_words.config(text=self.tr('none'))

            self.set_status(self.tr('status_analysis_complete'))
        except Exception as ex:
            messagebox.showerror(self.tr('error_analysis'), f"Error during analysis:\n{str(ex)}")
            self.set_status(self.tr('status_analysis_failed'))

    def action_clear(self):
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert("1.0", self.tr('placeholder_input'))
        self.lbl_pred.config(text="-", fg=self.FG_COLOR)
        self.lbl_conf.config(text="-")
        self.lbl_alert.config(text="-", fg=self.FG_COLOR)
        self.lbl_words.config(text=self.tr('none'))
        self.last_analysis = None
        # Reset options to initial values. Programmatic .set() does not fire
        # the Scale command callback, so refresh the value labels manually.
        self.med_thresh_var.set(0.65)
        self.high_thresh_var.set(0.85)
        self.lbl_med_val.config(text="0.65")
        self.lbl_high_val.config(text="0.85")
        self.harden_var.set(False)
        self.set_status(self.tr('status_cleared'))

    def action_save_report(self):
        if not self.last_analysis or self.last_analysis.get("prediction") == "-":
            messagebox.showinfo(self.tr('info_save_report'), self.tr('info_save_report_msg'))
            return

        save_path = filedialog.asksaveasfilename(
            title=self.tr('info_report_saved'),
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt"), ("All Files", "*.*")]
        )
        if not save_path:
            return

        self.set_status(self.tr('status_saving'))
        try:
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            raw_input = self.last_analysis.get("raw_input", "")
            preview_500 = raw_input[:500]

            top_words_str = ", ".join(
                f"{w} ({s:.5f})" for w, s in self.last_analysis.get("top_words", [])
            ) or self.tr('none')

            report_lines = [
                "=" * 60,
                " PHISHING DETECTOR - EMAIL ANALYSIS REPORT",
                "=" * 60,
                f"Timestamp:   {now_str}",
                f"Prediction:  {self.last_analysis['prediction']}",
                f"Confidence:  {self.last_analysis['confidence_str']}",
                f"Alert Tier:  {self.last_analysis['alert']}",
                "-" * 60,
                f"Top Contributing Words:\n{top_words_str}",
                "-" * 60,
                "Analyzed Content (First 500 characters):",
                preview_500,
                "=" * 60
            ]

            with open(save_path, "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines))

            self.set_status(self.tr('status_report_saved').format(os.path.basename(save_path)))
            messagebox.showinfo(self.tr('info_report_saved'), self.tr('info_report_saved_msg').format(save_path))
        except Exception as ex:
            messagebox.showerror(self.tr('error_save'), f"Failed to save report:\n{str(ex)}")
            self.set_status(self.tr('status_analysis_failed'))

    def action_batch_csv(self):
        file_path = filedialog.askopenfilename(
            title=self.tr('batch_csv'),
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        self.set_status(self.tr('status_batch_processing'))
        try:
            df = pd.read_csv(file_path)
            if df.empty:
                messagebox.showwarning(self.tr('warning_batch_empty'), self.tr('warning_batch_empty_msg'))
                self.set_status(self.tr('status_ready'))
                return

            # Find matching column
            target_col = None
            for col in df.columns:
                if str(col).strip().lower() in ("text", "email", "content", "body"):
                    target_col = col
                    break
            if target_col is None:
                target_col = df.columns[0]

            med = self.med_thresh_var.get()
            high = self.high_thresh_var.get()
            harden = self.harden_var.get()

            preds = []
            confs = []
            alerts = []

            for val in df[target_col]:
                res = analyze_email(str(val or ""), med, high, harden_first=harden)
                preds.append(res["prediction"])
                confs.append(res["confidence_str"])
                alerts.append(res["alert"])

            df_results = df.copy()
            df_results["Prediction"] = preds
            df_results["Confidence"] = confs
            df_results["Alert_Tier"] = alerts

            self.show_batch_window(df_results, os.path.basename(file_path))
            self.set_status(self.tr('status_batch_finished'))
        except Exception as ex:
            messagebox.showerror(self.tr('error_batch_csv'), f"Failed to process CSV file:\n{str(ex)}")
            self.set_status(self.tr('status_analysis_failed'))

    def show_batch_window(self, df_results: pd.DataFrame, file_name: str):
        win = tk.Toplevel(self.root)
        win.title(self.tr('batch_window_title').format(file_name))
        win.geometry("900x520")

        top_frame = ttk.Frame(win, padding=10)
        top_frame.pack(fill=tk.X)

        lbl = ttk.Label(
            top_frame,
            text=self.tr('batch_label').format(len(df_results), file_name),
            font=("Helvetica", 11, "bold")
        )
        lbl.pack(side=tk.LEFT)

        def export_results():
            out_path = filedialog.asksaveasfilename(
                title=self.tr('info_export_success'),
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
            )
            if not out_path:
                return
            try:
                df_results.to_csv(out_path, index=False)
                messagebox.showinfo(self.tr('info_export_success'), self.tr('info_export_success_msg').format(len(df_results), out_path))
            except Exception as e:
                messagebox.showerror(self.tr('error_export_failed'), self.tr('error_export_failed_msg').format(str(e)))

        btn_export = ttk.Button(top_frame, text=self.tr('export_button'), command=export_results)
        btn_export.pack(side=tk.RIGHT)

        # Treeview
        tree_frame = ttk.Frame(win, padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        display_cols = list(df_results.columns)
        tree = ttk.Treeview(tree_frame, columns=display_cols, show="headings")

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)

        for col in display_cols:
            tree.heading(col, text=col)
            tree.column(col, width=140, anchor="w")

        # Insert rows
        for _, row in df_results.iterrows():
            values = [str(row[c])[:120] for c in display_cols]
            tree.insert("", tk.END, values=values)


# ---------------------------------------------------------------------------
# 6. Sanity Check Test Mode (--test)
# ---------------------------------------------------------------------------

def run_test_mode():
    print("=" * 60)
    print(" RUNNING SANITY CHECK TEST MODE (--test)")
    print("=" * 60)

    try:
        load_artifacts()
        print("[OK] Model and vectorizer loaded successfully.")
    except Exception as e:
        print(f"[FAIL] Failed to load model artifacts: {e}")
        sys.exit(1)

    sample_legit = (
        "Subject: Team Sync Meeting Notes\n\n"
        "Hi Abubaker,\n"
        "Here are the minutes from today's weekly architecture meeting.\n"
        "Let me know if you have any questions regarding the schedule.\n"
        "Best regards,\nEngineering Team"
    )

    sample_phish = (
        "Subject: URGENT: Your Account Has Been Suspended!\n\n"
        "Dear Customer,\n"
        "Your access will be permanently terminated within 24 hours due to suspicious activity.\n"
        "Click here immediately to verify your identity and restore access: http://secure-login-update-verify.com/login\n"
        "Security Department"
    )

    print("\n--- Testing Sample 1 (Expected Legitimate) ---")
    res1 = analyze_email(sample_legit, med_thresh=0.65, high_thresh=0.85, harden_first=True)
    print(f"Prediction: {res1['prediction']}")
    print(f"Confidence: {res1['confidence_str']}")
    print(f"Alert Tier: {res1['alert']}")
    print(f"Top Words:  {res1['top_words']}")

    print("\n--- Testing Sample 2 (Expected Phishing) ---")
    res2 = analyze_email(sample_phish, med_thresh=0.65, high_thresh=0.85, harden_first=True)
    print(f"Prediction: {res2['prediction']}")
    print(f"Confidence: {res2['confidence_str']}")
    print(f"Alert Tier: {res2['alert']}")
    print(f"Top Words:  {res2['top_words']}")

    print("\n" + "=" * 60)
    print(" SANITY CHECK COMPLETED")
    print("=" * 60)
    sys.exit(0)


# ---------------------------------------------------------------------------
# 7. Main Entry Point
# ---------------------------------------------------------------------------

def main():
    if "--test" in sys.argv:
        run_test_mode()

    # Load artifacts on startup
    try:
        load_artifacts()
    except Exception as e:
        # Show graphical error dialog if Tkinter can be initialized
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Startup Error - Missing Model",
            f"Failed to load required model artifacts:\n\n{str(e)}\n\n"
            "Ensure 'random_forest_model.pkl' and 'random_forest_vectorizer.pkl' "
            "are placed in the same directory as this script."
        )
        sys.exit(1)

    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()