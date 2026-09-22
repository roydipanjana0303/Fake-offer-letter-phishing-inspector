# 🛡️ Phishing & Fake Job Offer Inspector

An intelligent web application that detects employment fraud, phishing recruitment emails, advance-fee training scams, and fake offer letters.

The system combines **three layers of defense**:
1. **Google Gemini AI**: Deep semantic reasoning, detecting advance fee requests, wire transfers, fake checks, and recruiter anomalies.
2. **Machine Learning Classifier**: Scikit-learn TF-IDF + Random Forest model trained on the Employment Scam Aegean Dataset (EMSCAD).
3. **WHOIS Domain Intelligence**: Real-time domain registration age and private WHOIS auditing to flag newly registered phishing domains.

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd phising-inspector
```

### 2. Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API Key
Copy the example environment file:
```bash
cp .env.example .env
```
Open `.env` and add your Google Gemini API key:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(Get a free API key at [Google AI Studio](https://aistudio.google.com/)).*

### 5. Run the Application
```bash
python3 app.py
```
Open your browser and navigate to:
**http://127.0.0.1:5000**

---

## 📁 Project Structure

```
├── app.py                # Flask backend with Gemini AI, ML pipeline & WHOIS lookup
├── templates/
│   └── index.html        # Interactive frontend with live health badge & drag-and-drop
├── train_model.py        # ML training script for scikit-learn classifier
├── job_scam_model.pkl    # Pre-trained job scam classification model
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variables template
└── .gitignore            # Git exclusions (API keys, venv, large CSVs)
```

---

## 🧪 Testing

- **Quick Scam Test**: Click **🚨 Load Scam Sample** in the UI to test advance-fee scam detection.
- **Legitimate Offer Test**: Click **✅ Load Legitimate Sample** to test legitimate offer analysis.
- **PDF Upload**: Drag and drop any PDF offer letter to automatically extract text and compute SHA-256 hash.
