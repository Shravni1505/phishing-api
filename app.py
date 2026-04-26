from flask import Flask, request, jsonify
import pickle, os, datetime
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

# Load ML model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Initialize Firebase (for Firestore logging)
if not firebase_admin._apps:
    cred = credentials.Certificate("firebase-key.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "Phishing Detection API is running!"})

@app.route("/detect", methods=["POST", "OPTIONS"])
def detect():
    if request.method == "OPTIONS":
        resp = jsonify({})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp, 204

    data = request.get_json()
    text = data.get("text", "").strip()

    if not text:
        return jsonify({"error": "text is required"}), 400

    pred  = model.predict([text])[0]
    proba = model.predict_proba([text])[0]
    label = "phishing" if pred == 1 else "safe"
    conf  = round(float(proba[pred]), 4)

    # Log to Firestore
    log_id = None
    try:
        doc = db.collection("phishing_logs").add({
            "text":       text,
            "label":      label,
            "confidence": conf,
            "timestamp":  datetime.datetime.utcnow().isoformat()
        })
        log_id = doc[1].id
    except Exception as e:
        print(f"Firestore log failed: {e}")

    resp = jsonify({
        "label":      label,
        "confidence": conf,
        "message":    "⚠️ PHISHING detected!" if pred == 1 else "✅ Message is SAFE.",
        "log_id":     log_id
    })
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)