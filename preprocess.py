import pandas as pd
import re

df = pd.read_csv("data/phishing_email.csv")
# Drop any missing rows
df = df.dropna(subset=["text_combined", "label"])

# Basic cleaning function
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' url ', text)   # replace links with a token
    text = re.sub(r'[^a-z\s]', ' ', text)              # remove numbers/punctuation
    text = re.sub(r'\s+', ' ', text).strip()           # remove extra spaces
    return text

df["clean_text"] = df["text_combined"].apply(clean_text)

# Check email length stats (useful for your report)
df["length"] = df["clean_text"].apply(lambda x: len(x.split()))
print("Average word count:", df["length"].mean())
print("Max word count:", df["length"].max())
print("Min word count:", df["length"].min())

# Remove empty or extremely long outlier emails
df = df[df["length"] > 0]
df = df[df["length"] < 2000]  # drop unrealistic outliers
print("\nShape after filtering:", df.shape)

# Save cleaned version so we don't redo this every time
df.to_csv("data/cleaned_emails.csv", index=False)
print("\nSaved cleaned_emails.csv")
print(df[["clean_text", "label"]].head(3))
