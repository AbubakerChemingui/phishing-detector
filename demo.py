import joblib
import re
import sys

model = joblib.load("random_forest_model.pkl")
vectorizer = joblib.load("random_forest_vectorizer.pkl")

def clean_email_text(raw_text):
    raw_text = str(raw_text).lower()
    raw_text = re.sub(r'http\S+|www\S+', ' url ', raw_text)
    raw_text = re.sub(r'[^a-z\s]', ' ', raw_text)
    raw_text = re.sub(r'\s+', ' ', raw_text).strip()
    return raw_text

# turns the raw prediction + confidence into a readable alert level
def get_alert(prediction, confidence):
    if prediction == 1:  # phishing
        if confidence >= 0.85:
            return "HIGH RISK - likely phishing"
        elif confidence >= 0.65:
            return "MEDIUM RISK - possibly phishing"
        else:
            return "LOW CONFIDENCE - uncertain, review manually"
    else:  # legit
        if confidence >= 0.85:
            return "SAFE - likely legitimate"
        elif confidence >= 0.65:
            return "LIKELY SAFE - probably legitimate"
        else:
            return "LOW CONFIDENCE - uncertain, review manually"

print("Phishing Email Detector (Random Forest) - paste your email below")
print("When finished, type END on its own line\n")

lines = []
while True:
    try:
        line = input()
    except EOFError:
        break
    if line.strip().upper() == "END":
        break
    lines.append(line)

email_text = "\n".join(lines)
cleaned = clean_email_text(email_text)

if not cleaned:
    # Nothing to classify: an empty string becomes a zero TF-IDF vector,
    # which the model reads as phishing (fail-closed bias). Refuse instead,
    # mirroring core.analyze_email's "please enter e-mail text" behavior.
    print("\nResult: NO CONTENT (confidence: -)")
    print("Alert:  Please paste an email to analyse - empty input cannot be classified.")
    sys.exit(0)

X = vectorizer.transform([cleaned])
prediction = model.predict(X)[0]
confidence = model.predict_proba(X)[0][prediction]

label = "PHISHING" if prediction == 1 else "LEGIT"
alert = get_alert(prediction, confidence)

print(f"\nResult: {label} (confidence: {confidence:.2%})")
print(f"Alert:  {alert}")
