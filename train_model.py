import os
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

CSV_PATH = "fake_job_postings.csv"

if not os.path.exists(CSV_PATH):
    print(f"Error: {CSV_PATH} not found. Please place the dataset in the project root.")
    exit(1)

print("Loading dataset...")
df = pd.read_csv(CSV_PATH)
df['combined_text'] = (
    df['title'].fillna('') + ' ' +
    df['company_profile'].fillna('') + ' ' +
    df['description'].fillna('') + ' ' +
    df['requirements'].fillna('')
)

X = df['combined_text']
y = df['fraudulent']

print("Fitting TF-IDF vectorizer and RandomForestClassifier...")
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=3000, stop_words='english')),
    ('clf', RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'))
])

pipeline.fit(X, y)
joblib.dump(pipeline, 'job_scam_model.pkl')
print("Model created successfully: job_scam_model.pkl")
