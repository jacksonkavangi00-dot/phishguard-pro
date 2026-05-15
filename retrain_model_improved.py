import pandas as pd
import numpy as np
import joblib
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix

print("🔄 Retraining PhishGuard with improved data...\n")

# ==================== FEATURE EXTRACTION ====================
def extract_features_13(url):
    url = str(url).lower()
    features = []
    
    features.append(min(len(url) / 200, 1.0))
    features.append(min(url.count('.') / 10, 1.0))
    features.append(min(url.count('-') / 5, 1.0))
    features.append(min(url.count('_') / 5, 1.0))
    features.append(min(url.count('/') / 20, 1.0))
    features.append(min(url.count('?') / 10, 1.0))
    features.append(min(url.count('=') / 10, 1.0))
    features.append(1 if url.startswith('https') else 0)
    features.append(1 if '@' in url else 0)
    
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features.append(min(digits / max(letters, 1), 1.0))
    
    suspicious = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 
                  'bank', 'paypal', 'signin', 'authenticate', 'password', 'credential']
    features.append(sum(1 for word in suspicious if word in url) / len(suspicious))
    
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
    features.append(1 if any(s in url for s in shorteners) else 0)
    
    return np.array(features)

# ==================== LOAD DATA ====================
print("📂 Loading improved dataset...")
df = pd.read_csv('improved_training_data.csv')
print(f"Loaded {len(df)} URLs")
print(df['label'].value_counts())

# ==================== FEATURE EXTRACTION ====================
print("\n🔧 Extracting features...")
feature_list = []
for url in df['url']:
    feature_list.append(extract_features_13(url))
X_features = np.array(feature_list)

# ==================== TF-IDF ====================
print("📝 Applying TF-IDF...")
vectorizer = TfidfVectorizer(
    analyzer='char',
    ngram_range=(3, 5),
    max_features=2000,
    sublinear_tf=True
)
X_text = vectorizer.fit_transform(df['url'])

# ==================== COMBINE ====================
X = hstack([X_text, csr_matrix(X_features)])
y = df['label'].values

print(f"Feature matrix: {X.shape}")

# ==================== TRAIN ====================
print("\n🚀 Training Random Forest...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# ==================== EVALUATE ====================
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n✅ Model Accuracy: {accuracy * 100:.2f}%")

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

# Test on problematic patterns
print("\n🧪 Testing on problematic URL patterns:")

test_urls = [
    "https://youtube.com/watch?v=W8a4sUabCUo",
    "https://youtu.be/abc123",
    "https://google.com/search?q=test",
    "https://github.com/user/repo/issues/123",
    "http://secure-paypal-login-update.com",
    "http://bit.ly/fake-login",
]

for url in test_urls:
    features = extract_features_13(url)
    X_text = vectorizer.transform([url])
    X_test_url = hstack([X_text, csr_matrix([features])])
    pred = model.predict(X_test_url)[0]
    prob = model.predict_proba(X_test_url)[0].max()
    result = "🔴 PHISHING" if pred == 1 else "🟢 SAFE"
    print(f"  {result} ({prob*100:.1f}%) | {url[:70]}")

# ==================== SAVE ====================
print("\n💾 Saving improved model...")
joblib.dump(model, 'model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("✅ Model retrained and saved!")
