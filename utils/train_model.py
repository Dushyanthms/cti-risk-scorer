import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
import os

print("📂 Loading dataset...")

# Load dataset
df = pd.read_csv("Data/malicious_phish.csv")

X = df["url"]
y = df["type"]

# Vectorize
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
X_vec = vectorizer.fit_transform(X)

# Train with incremental learning model
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

model = SGDClassifier(loss="log_loss", random_state=42)
model.partial_fit(X_train, y_train, classes=y.unique())

# Evaluate
acc = model.score(X_test, y_test)
print(f"✅ Initial model accuracy: {acc:.4f}")

# Save model & vectorizer
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")
print("🎉 Initial Model & Vectorizer saved!")