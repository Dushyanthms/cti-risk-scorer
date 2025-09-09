from flask import Flask, render_template, request, redirect, url_for, session
import joblib
import json
import re
import os
import pandas as pd
from datetime import datetime

# ================= CONFIG =================
with open("config.json", "r") as f:
    config = json.load(f)

# Override sensitive values with environment variables if present
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", config.get("ADMIN_USERNAME", "admin"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", config.get("ADMIN_PASSWORD", "admin123"))
SAFE_DOMAINS = config.get("SAFE_DOMAINS", [])
IP_RULES = config["IP_RULES"]
HASH_RULES = config["HASH_RULES"]
THRESHOLDS = config["THRESHOLDS"]

MODEL_PATH = "models/model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"
FEEDBACK_FILE = "feedback.json"
FEEDBACK_CSV = "feedback.csv"  # root-level file
DATASET_FILE = "Data/malicious_phish.csv"

# ================= APP INIT =================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-please-change")

# ================= MODEL LOAD =================
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

# ================= HELPERS =================
def is_whitelisted(ioc_value):
    return any(domain in ioc_value.lower() for domain in SAFE_DOMAINS)

def check_ip(ip):
    for rule in IP_RULES:
        if re.match(rule, ip):
            return {"prediction": "malicious", "risk_score": 95, "confidence": 95.0}
    return {"prediction": "benign", "risk_score": 5, "confidence": 95.0}

def check_hash(hval):
    for bad_hash in HASH_RULES:
        if hval == bad_hash:
            return {"prediction": "malicious", "risk_score": 99, "confidence": 99.0}
    return {"prediction": "benign", "risk_score": 1, "confidence": 99.0}

# ================= ROUTES =================
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    ioc_type = request.form.get("ioc_type")
    ioc_value = request.form.get("ioc_value")
    result = {"ioc_type": ioc_type, "ioc_value": ioc_value}

    if is_whitelisted(ioc_value):
        result.update({"prediction": "benign", "risk_score": 0, "confidence": 100.0})

    elif ioc_type in ["url", "domain"]:
        X = vectorizer.transform([ioc_value])
        prediction = model.predict(X)[0]
        probas = model.predict_proba(X)[0]
        confidence = round(max(probas) * 100, 2)
        risk_score = round(confidence)
        result.update({
            "prediction": prediction,
            "risk_score": risk_score,
            "confidence": confidence
        })

    elif ioc_type == "ip":
        result.update(check_ip(ioc_value))

    elif ioc_type == "hash":
        result.update(check_hash(ioc_value))

    else:
        result.update({"prediction": "unknown", "risk_score": 0, "confidence": 0})

    return render_template("index.html", result=result)

# ================= FEEDBACK =================
@app.route("/feedback", methods=["POST"])
def feedback():
    ioc_value = request.form.get("ioc_value")
    feedback_choice = request.form.get("feedback")

    data = []
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "r") as f:
            data = json.load(f)

    data.append({
        "ioc_value": ioc_value,
        "feedback": feedback_choice,
        "user_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    with open(FEEDBACK_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return redirect(url_for("home"))

# ================= ADMIN =================
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("feedback_view"))
        else:
            return render_template("admin_login.html", error="❌ Invalid credentials")

    return render_template("admin_login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/feedback-view", methods=["GET", "POST"])
def feedback_view():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    feedbacks = []
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "r") as f:
            feedbacks = json.load(f)

    dataset = pd.read_csv(DATASET_FILE)
    dataset_lookup = dict(zip(dataset["url"], dataset["type"]))  # fast lookup

    if request.method == "POST":
        action = request.form.get("action")
        ioc_value = request.form.get("ioc_value")

        updated_feedbacks = []
        for fb in feedbacks:
            if fb["ioc_value"] == ioc_value:
                if action == "delete":
                    continue  # skip this entry (delete it)
                fb["admin_action"] = action
                fb["admin_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            updated_feedbacks.append(fb)
        feedbacks = updated_feedbacks

        # Write to CSV when admin validates
        if action in ["safe", "risky"]:
            label = "benign" if action == "safe" else "phishing"
            row = pd.DataFrame([[ioc_value, label]], columns=["url", "type"])

            if os.path.exists(FEEDBACK_CSV):
                row.to_csv(FEEDBACK_CSV, mode="a", header=False, index=False)
            else:
                row.to_csv(FEEDBACK_CSV, index=False)

            print(f"✅ Saved feedback to {FEEDBACK_CSV}: {ioc_value} → {label}")

        with open(FEEDBACK_FILE, "w") as f:
            json.dump(feedbacks, f, indent=4)

        return redirect(url_for("feedback_view"))

    # Show dataset status
    for fb in feedbacks:
        if fb["ioc_value"] in dataset_lookup:
            fb["exists_in_dataset"] = True
            fb["dataset_label"] = dataset_lookup[fb["ioc_value"]]
        else:
            fb["exists_in_dataset"] = False
            fb["dataset_label"] = "NEW IOC"

    return render_template("feedback.html", feedbacks=feedbacks)

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True, port=5001)