import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
import os

print("📂 Loading dataset...")

# Load dataset
df = pd.read_csv("Data/malicious_phish.csv")

X = df["url"]
y = df["type"]

# Check if model/vectorizer exist
if os.path.exists("models/model.pkl") and os.path.exists("models/vectorizer.pkl"):
    print("🔄 Loading existing model for incremental training...")
    model = joblib.load("models/model.pkl")
    vectorizer = joblib.load("models/vectorizer.pkl")

    X_vec = vectorizer.transform(X)

    # Incremental update
    model.partial_fit(X_vec, y, classes=model.classes_)

else:
    print("✨ No existing model found. Training from scratch...")
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
    X_vec = vectorizer.fit_transform(X)

    model = SGDClassifier(loss="log_loss", random_state=42)
    model.partial_fit(X_vec, y, classes=y.unique())

# Save updated model
joblib.dump(model, "models/model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")
print("🎉 Model & Vectorizer updated with incremental training!")