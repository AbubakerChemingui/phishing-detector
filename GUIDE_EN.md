# Phishing Email Detection System - User Guide (English)

## Introduction
This guide explains how to use the Phishing Email Detection System, which includes a desktop GUI, command-line interface, email firewall (IMAP scanner), and a web-based Streamlit app. The system detects phishing emails using a pre-trained Random Forest model with TF‑IDF vectorization.

## System Requirements
- Python 3.8 or higher
- Required packages: tkinter, scikit-learn, joblib, numpy, pandas, streamlit (for web app)
- The model files `random_forest_model.pkl` and `random_forest_vectorizer.pkl` must be present in the application directory.

## Installation
1. Ensure Python is installed.
2. Install dependencies (if not already installed):
   ```bash
   pip install scikit-learn joblib numpy pandas streamlit
   ```
3. Place the model files in the same folder as the scripts.
4. No further installation is needed.

## Usage

### 1. Desktop GUI (Tkinter)
Run the GUI:
```bash
python gui_app.py
```
Features:
- **Language Selection**: Choose English, French, or Arabic from the dropdown in the Options pane.
- **Theme**: Toggle dark mode with `Alt+D` or change accent colour with `Alt+A` (or keys 1‑5).
- **Analyze an Email**:
  1. Paste the full email (including headers) into the left pane.
  2. Optionally enable **Hardening** to detect obfuscation techniques.
  3. Adjust **Medium** and **High** risk thresholds via sliders (default 0.65 and 0.85).
  4. Click **Check Email** or press `Ctrl+Enter`.
  5. Results appear in the right pane:
     - Prediction (Phishing/Legitimate)
     - Confidence percentage
     - Alert tier (SAFE, LIKELY SAFE, LOW CONFIDENCE, etc.)
     - Top contributing words (TF‑IDF × feature importance)
- **Additional Buttons**:
  - **Open .eml/.txt**: Load an email file.
  - **Clear**: Reset input and results.
  - **Batch CSV**: Analyze a CSV file containing email texts (one per row).
  - **Save Report**: Export the current analysis to a text file.
- **Keyboard Shortcuts**:
  - `Ctrl+Enter`: Analyze email
  - `Alt+D`: Toggle theme (black / dark gray)
  - `Alt+A`: Cycle accent colour
  - `1‑5`: Select accent colour directly
  - `F1` or `?`: Show cheat sheet
  - `Esc`: Blur focus (return to root)
  - `Enter` in input box: Quick analysis (same as Ctrl+Enter)

### 2. Command‑Line Interface (CLI)
Use `demo.py` to analyze a single email from standard input:
```bash
echo "Subject: Test\n\nHello world" | python demo.py
```
The tool outputs the prediction (PHISHING or LEGITIMATE) and confidence.

### 3. Email Firewall (IMAP Scanner)
`email_firewall.py` monitors an IMAP mailbox and flags phishing emails.
- Edit the script to set your IMAP server, email, and password (or use environment variables).
- Run:
  ```bash
  python email_firewall.py
  ```
- The script will scan incoming emails and print those detected as phishing.

### 4. Web Interface (Streamlit)
Run the Streamlit app:
```bash
streamlit run app.py
```
Features:
- Text area for email input.
- Sidebar options: Enable hardening, adjust thresholds.
- **Analyze Email** button to run analysis.
- Displays prediction, confidence, alert tier, and top contributing words.

## Features
- **Pre‑processing**: Lowercasing, URL replacement, punctuation removal, space normalization.
- **Hardening Options** (optional): Unicode NFKC normalization, homoglyph replacement, leet‑speak decoding, zero‑width character stripping.
- **Explainability**: Shows top contributing words to help understand why an email was flagged.
- **Configurable Thresholds**: Adjust medium and high risk levels to suit your environment.
- **Multi‑language Support**: GUI language can be switched at runtime (English, French, Arabic).
- **Multiple Interfaces**: Choose the interface that best fits your workflow.

## Troubleshooting
- **Model not found**: Ensure `random_forest_model.pkl` and `random_forest_vectorizer.pkl` are in the same directory as the script.
- **GUI does not start**: Verify that tkinter is installed (usually bundled with Python).
- **Streamlit fails**: Install streamlit with `pip install streamlit`.
- **No text in GUI**: Make sure you have pasted email content; the placeholder text disappears when focused.
- **Batch CSV errors**: Ensure the CSV contains a column with email text (named text, email, content, or body) or the first column will be used.

## Support
For issues or questions, consult the `SYSTEM_REPORT.md` file for technical details and test results.

--- 

*End of Guide*