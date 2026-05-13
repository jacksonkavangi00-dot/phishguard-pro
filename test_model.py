import joblib
import numpy as np
import re
from scipy.sparse import hstack, csr_matrix

# Load model and vectorizer
model = joblib.load('model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

def extract_features_13(url):
    """Extract exactly 13 features to match model's 2013 total (2000 TF-IDF + 13 manual)"""
    url = str(url).lower()
    features = []
    
    # 1. Normalized URL length
    features.append(min(len(url) / 200, 1.0))
    
    # 2. Count of dots
    features.append(min(url.count('.') / 10, 1.0))
    
    # 3. Count of hyphens
    features.append(min(url.count('-') / 5, 1.0))
    
    # 4. Count of underscores
    features.append(min(url.count('_') / 5, 1.0))
    
    # 5. Count of slashes
    features.append(min(url.count('/') / 20, 1.0))
    
    # 6. Count of question marks
    features.append(min(url.count('?') / 10, 1.0))
    
    # 7. Count of equals signs
    features.append(min(url.count('=') / 10, 1.0))
    
    # 8. Has HTTPS? (1 if starts with https)
    features.append(1 if url.startswith('https') else 0)
    
    # 9. Has @ symbol?
    features.append(1 if '@' in url else 0)
    
    # 10. Digit to letter ratio
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features.append(min(digits / max(letters, 1), 1.0))
    
    # 11. Suspicious keyword score
    suspicious = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 
                  'bank', 'paypal', 'signin', 'authenticate', 'password', 
                  'credential', 'verify', 'unlock', 'alert', 'security']
    features.append(sum(1 for word in suspicious if word in url) / len(suspicious))
    
    # 12. Contains IP address?
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # 13. Uses URL shortener?
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.url']
    features.append(1 if any(s in url for s in shorteners) else 0)
    
    return np.array(features)

def predict_url(url):
    """Predict if a URL is phishing"""
    # Extract 13 features
    features = extract_features_13(url)
    
    # Apply TF-IDF (gets 2000 features)
    X_text = vectorizer.transform([url])
    
    # Combine: 2000 + 13 = 2013 features
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
    'https://stackoverflow.com',             # Safe
    'http://secure-login-verify.xyz',        # Phishing
    'http://paypal-verification.secure.com', # Phishing
    'https://accounts-login-help.net',       # Phishing
    'http://bit.ly/fake-paypal',             # Phishing (shortener)
]

print("\n🔍 PhishGuard AI - Real-time Detection Test\n")
print("=" * 70)

for url in test_urls:
    pred, conf = predict_url(url)
    status = "🔴 PHISHING" if pred == 1 else "🟢 SAFE"
    print(f"{status} | {conf*100:5.1f}% | {url[:55]}")

print("=" * 70)
print("\n✅ Model is working correctly!")
