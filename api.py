#!/usr/bin/env python3
"""
api.py - Lightweight HTTP API for real-time Random Forest predictions.
Runs on port 5001 and enables the React frontend to query the real model.
"""
from __future__ import annotations

import json
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import joblib
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "url-guard", "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from features import extract_features, feature_names

# Load model
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "random_forest_model.joblib")
if not os.path.exists(MODEL_PATH):
    # Fallback to other extensions
    for ext in ["xz", "pkl"]:
        candidate = os.path.join(PROJECT_ROOT, "models", f"random_forest_model.{ext}")
        if os.path.exists(candidate):
            MODEL_PATH = candidate
            break

print(f"[*] Loading trained Random Forest champion from: {MODEL_PATH}")
model = joblib.load(MODEL_PATH)
print("[+] Model loaded successfully!")

class PredictionHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/predict":
            qs = parse_qs(parsed.query)
            raw_url = qs.get("url", [""])[0]
            self.handle_predict(raw_url)
        elif parsed.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "model": "Random Forest (100 Trees)"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/predict":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                raw_url = data.get("url", "")
            except Exception:
                raw_url = ""
            self.handle_predict(raw_url)
        else:
            self.send_response(404)
            self.end_headers()

    def handle_predict(self, raw_url: str):
        if not raw_url.strip():
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Missing URL parameter"}).encode("utf-8"))
            return

        t0 = time.perf_counter()
        feats = extract_features(raw_url)
        names = feature_names()
        
        # Build feature vector matching model expectations
        vec = [feats.get(name, 0) for name in names]
        df = pd.DataFrame([vec], columns=names)

        # Run inference
        probs = model.predict_proba(df)[0]
        malicious_prob = float(probs[1])
        prediction = "malicious" if malicious_prob >= 0.5 else "benign"
        latency_ms = (time.perf_counter() - t0) * 1000

        response = {
            "url": raw_url,
            "prediction": prediction,
            "probability": malicious_prob,
            "latency_ms": round(latency_ms, 3),
            "features": feats,
            "engine": "Scikit-Learn Random Forest (100 Trees)"
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        # Silence verbose logging
        pass

def main():
    port = 5001
    server = HTTPServer(("127.0.0.1", port), PredictionHandler)
    print(f"[+] Prediction API serving live at http://127.0.0.1:{port}/api/predict")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
