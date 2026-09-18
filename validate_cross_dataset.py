import os
import sys
import pandas as pd
import joblib
import re
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# The XGBoost artifacts live in the old project copy, not in this repo
# (large binaries are intentionally untracked - see DATA_SOURCES.md).
for _needed in ("phishing_model.pkl", "tfidf_vectorizer.pkl"):
    if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), _needed)):
        print(f"error: '{_needed}' is not in this folder.")
        print("It lives in the old project copy at C:\\Users\\Abubaker\\phishing-detector\\")
        print("Copy it next to this script to run this validation, or use")
        print("evaluate_saved_model.py ( Random Forest, same holdout ) instead.")
        sys.exit(1)

trained_model = joblib.load("phishing_model.pkl")
tfidf_vectorizer = joblib.load("tfidf_vectorizer.pkl")

new_data = pd.read_csv("data/validation/Phishing_Email.csv")
print("Columns in this dataset:", new_data.columns.tolist())

email_column = "Email Text" if "Email Text" in new_data.columns else new_data.columns[1]
label_column = "Email Type" if "Email Type" in new_data.columns else new_data.columns[2]
print(f"Using '{email_column}' as the email text column and '{label_column}' as the label column")

new_data = new_data.dropna(subset=[email_column, label_column])

new_data["label"] = new_data[label_column].apply(lambda x: 1 if "phish" in str(x).lower() else 0)

print("\nPhishing vs legit email counts in this new dataset:")
print(new_data["label"].value_counts())

def clean_email_text(raw_text):
    raw_text = str(raw_text).lower()
    raw_text = re.sub(r'http\S+|www\S+', ' url ', raw_text)
    raw_text = re.sub(r'[^a-z\s]', ' ', raw_text)
    raw_text = re.sub(r'\s+', ' ', raw_text).strip()
    return raw_text

new_data["cleaned_text"] = new_data[email_column].apply(clean_email_text)
new_data = new_data[new_data["cleaned_text"].str.len() > 0]

X_test = tfidf_vectorizer.transform(new_data["cleaned_text"])
y_test = new_data["label"]

y_pred = trained_model.predict(X_test)

print("\n=== XGBoost performance on a completely unseen dataset ===")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))
print("F1-score:", f1_score(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
