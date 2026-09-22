import os
import re
import json
import hashlib
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import whois
from pypdf import PdfReader
from google import genai
from google.genai import types
from dotenv import load_dotenv
import joblib

load_dotenv()

app = Flask(__name__, template_folder="templates")
CORS(app)  # Allows cross-origin requests from any local IP or domain

# Initialize Gemini Client
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_KEY) if GEMINI_KEY else None

# Candidate Gemini models in order of priority
CANDIDATE_MODELS = ["gemini-3.5-flash-lite", "gemini-3.6-flash", "gemini-flash-latest"]

# Optional ML model loader
ml_model = None
def load_ml_model():
    global ml_model
    if ml_model is None:
        for p in ["job_scam_model.pkl", "templates/job_scam_model.pkl"]:
            if os.path.exists(p):
                try:
                    ml_model = joblib.load(p)
                    print(f"Loaded ML model from {p}")
                    break
                except Exception as e:
                    print(f"Notice: ML model not loaded from {p}: {e}")
    return ml_model

load_ml_model()

HIGH_RISK_KEYWORDS = [
    r"unpaid", r"training\s*fee", r"security\s*deposit", r"zelle", 
    r"crypto", r"telegram", r"whatsapp\s*only", r"advance\s*deposit",
    r"cashier\s*check", r"wire\s*transfer", r"gift\s*card"
]

def analyze_domain(url_or_domain):
    if not url_or_domain:
        return {"domain": None, "age_days": None, "flagged": False, "reasons": []}
    
    clean_domain = re.sub(r'https?://', '', url_or_domain).split('/')[0].split(':')[0]
    
    try:
        w = whois.whois(clean_domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        reasons = []
        if creation_date:
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            
            age_days = (now - creation_date).days
            if age_days < 180:
                reasons.append(f"Newly registered domain ({age_days} days old)")
            return {"domain": clean_domain, "age_days": age_days, "flagged": age_days < 180, "reasons": reasons}
        return {"domain": clean_domain, "age_days": None, "flagged": False, "reasons": ["Registration date private"]}
    except Exception as e:
        return {"domain": clean_domain, "age_days": None, "flagged": False, "reasons": [f"WHOIS check skipped ({str(e)})"]}

def scan_regex_keywords(text):
    found = []
    for pattern in HIGH_RISK_KEYWORDS:
        if re.search(pattern, text, re.IGNORECASE):
            readable_pattern = pattern.replace(r"\s*", " ")
            found.append(f"Risk keyword found: '{readable_pattern}'")
    return found

def predict_ml_scam(text):
    model = load_ml_model()
    if not model or not text:
        return None
    try:
        probs = model.predict_proba([text])[0]
        classes = list(model.classes_)
        if 1 in classes:
            idx = classes.index(1)
            return int(round(probs[idx] * 100))
        return int(round(probs[-1] * 100))
    except Exception as e:
        print(f"ML prediction error: {e}")
        return None

def analyze_with_gemini(text):
    if not client:
        return {
            "risk_score": 50,
            "detected_red_flags": ["GEMINI_API_KEY missing in .env file"],
            "payment_demand_present": False,
            "verdict_summary": "Gemini API Key missing. Showing local analysis only."
        }

    prompt = f"""
    You are an expert cybersecurity and fraud analyst. Analyze the following offer or email text for employment fraud, unpaid training scams, advance fee scams, check overpayment schemes, or fake recruiters.

    Offer Text:
    \"\"\"{text[:4000]}\"\"\"

    Return ONLY a single valid JSON object without markdown fences or extra words:
    {{
        "risk_score": <integer from 0 to 100, where 0 is legitimate and 100 is high risk scam>,
        "detected_red_flags": [<array of specific concise red flag strings identified>],
        "payment_demand_present": <boolean, true if requesting payment, bank details, checks, or fees>,
        "verdict_summary": "<concise 1-2 sentence assessment>"
    }}
    """

    last_err = None
    for model_name in CANDIDATE_MODELS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            raw = response.text.strip()
            # Extract JSON substring
            match = re.search(r'\{[\s\S]*\}', raw)
            if match:
                data = json.loads(match.group(0))
                return {
                    "risk_score": int(data.get("risk_score", 50)),
                    "detected_red_flags": list(data.get("detected_red_flags", [])),
                    "payment_demand_present": bool(data.get("payment_demand_present", False)),
                    "verdict_summary": str(data.get("verdict_summary", "AI analysis complete."))
                }
        except Exception as e:
            last_err = e
            continue

    return {
        "risk_score": 40,
        "detected_red_flags": [f"Cloud AI check unavailable: {str(last_err)}"],
        "payment_demand_present": False,
        "verdict_summary": "Cloud AI service temporarily busy. Local heuristic scanner applied."
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "Phishing & Fake Offer Inspector API",
        "gemini_configured": bool(client),
        "ml_model_loaded": bool(load_ml_model() is not None),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@app.route("/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    try:
        text_content = request.form.get("text", "").strip()
        company_url = request.form.get("url", "").strip()
        file_hash = None

        if 'file' in request.files:
            uploaded_file = request.files['file']
            if uploaded_file and uploaded_file.filename.lower().endswith('.pdf'):
                file_bytes = uploaded_file.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                try:
                    uploaded_file.seek(0)
                    reader = PdfReader(uploaded_file)
                    extracted = "".join([page.extract_text() or "" for page in reader.pages])
                    if extracted.strip():
                        text_content = f"{text_content}\n\n[PDF Extracted Text]:\n{extracted}".strip()
                except Exception as e:
                    print(f"PDF extraction error: {e}")

        if not text_content and not company_url:
            return jsonify({"error": "Please provide offer text, a domain URL, or attach a PDF file."}), 400

        # Run analysis checks
        domain_res = analyze_domain(company_url) if company_url else {"flagged": False, "reasons": []}
        regex_flags = scan_regex_keywords(text_content) if text_content else []
        ml_score = predict_ml_scam(text_content) if text_content else None
        ai_res = analyze_with_gemini(text_content) if text_content else {
            "risk_score": 0, "detected_red_flags": [], "payment_demand_present": False, "verdict_summary": "No text content provided."
        }

        # Calculate combined threat index
        all_flags = list(ai_res.get("detected_red_flags", [])) + regex_flags

        if ml_score is not None:
            if ml_score >= 60:
                all_flags.append(f"ML Model Alert: {ml_score}% probability of fraudulent posting pattern")

        ai_score = ai_res.get("risk_score", 0)
        if ml_score is not None and text_content:
            base_score = int(0.6 * ai_score + 0.4 * ml_score)
        else:
            base_score = ai_score

        final_score = base_score
        if domain_res.get("flagged"):
            final_score += 20
            all_flags.extend(domain_res.get("reasons", []))

        if regex_flags:
            final_score = max(final_score, min(95, 45 + 10 * len(regex_flags)))

        final_score = min(100, max(0, final_score))

        return jsonify({
            "scam_threat_index": final_score,
            "document_sha256": file_hash,
            "domain_info": domain_res,
            "audit_red_flags": sorted(list(set(all_flags))),
            "summary": ai_res.get("verdict_summary"),
            "ml_probability": ml_score,
            "payment_demand_detected": ai_res.get("payment_demand_present", False)
        }), 200

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)