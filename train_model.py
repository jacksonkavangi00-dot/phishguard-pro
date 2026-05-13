import joblib
import numpy as np
import re
from scipy.sparse import hstack, csr_matrix

# Load model and vectorizer
model = joblib.load('model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

def extract_features_full(url):
    """Must match the exact function used in training"""
    url = str(url).lower()
    features = []
    
    # Length features
    features.append(min(len(url) / 200, 1.0))
    features.append(min(url.count('.') / 10, 1.0))
    features.append(min(url.count('-') / 5, 1.0))
    features.append(min(url.count('_') / 5, 1.0))
    features.append(min(url.count('/') / 20, 1.0))
    features.append(min(url.count('?') / 10, 1.0))
    features.append(min(url.count('=') / 10, 1.0))
    
    # Security indicators
    features.append(1 if url.startswith('https') else 0)
    features.append(1 if '@' in url else 0)
    
    # Digit to letter ratio
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features.append(min(digits / max(letters, 1), 1.0))
    
    # Suspicious keywords
    suspicious = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 
                  'bank', 'paypal', 'signin', 'authenticate', 'password', 
                  'credential', 'verify', 'unlock', 'alert', 'security']
    features.append(sum(1 for word in suspicious if word in url) / len(suspicious))
    
    # IP address in URL
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.url']
    features.append(1 if any(s in url for s in shorteners) else 0)
    
    return np.array(features)

def predict_url(url):
    """Predict if a URL is phishing"""
    # Extract features
    features = extract_features_full(url)
    
    # Apply TF-IDF
    X_text = vectorizer.transform([url])
    
    # Combine features
    X = hstack([X_text, csr_matrix([features])])
    
    # Predict
    prediction = model.predict(X)[0]
    confidence = model.predict_proba(X)[0].max()
    
    return prediction, confidence

# Test URLs
test_urls = [
    'https://google.com',                    # Safe
    'https://paypal.com',                    # Safe
    'https://github.com',                    # Safe
    'http://secure-login-verify.xyz',        # Phishing
    'http://paypal-verification.secure.com', # Likely phishing
    'https://accounts-login-help.net',       # Likely phishing
]

print("\n🔍 PhishGuard AI Testing\n")
print("=" * 60)

for url in test_urls:
    pred, conf = predict_url(url)
    status = "🔴 PHISHING" if pred == 1 else "🟢 SAFE"
    print(f"{status} | Confidence: {conf*100:.1f}% | URL: {url[:60]}")

print("=" * 60)
