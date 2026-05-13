from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, Optional
import joblib
import numpy as np
import re
from scipy.sparse import hstack, csr_matrix
from datetime import datetime
import uuid
from urllib.parse import urlparse
import socket
from functools import lru_cache
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

# ==================== RATE LIMITING & API KEYS ====================
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import secrets
from datetime import timedelta

# ==================== FASTAPI INIT ====================
app = FastAPI(
    title="PhishGuard Pro API",
    description="AI-Powered Phishing URL Detection with WHOIS Intelligence",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Thread pool for WHOIS lookups
executor = ThreadPoolExecutor(max_workers=2)

# ==================== API KEY MANAGEMENT ====================
# In production, store these in a database
# For now, use a simple dict (upgrade to Redis later)
API_KEYS = {
    "free_demo_key": {"plan": "free", "rate_limit": "10/day", "requests_used": 0, "created_at": datetime.now().isoformat()},
    "pro_key_123": {"plan": "pro", "rate_limit": "1000/day", "requests_used": 0, "created_at": datetime.now().isoformat()},
    "enterprise_key_456": {"plan": "enterprise", "rate_limit": "10000/day", "requests_used": 0, "created_at": datetime.now().isoformat()},
}

# Track daily usage (in production, use Redis or database)
daily_usage = {}

def generate_api_key(plan: str = "free") -> dict:
    """Generate a new API key for a user"""
    api_key = secrets.token_urlsafe(32)
    API_KEYS[api_key] = {
        "plan": plan,
        "rate_limit": "1000/day" if plan == "pro" else "5000/day" if plan == "business" else "10000/day" if plan == "enterprise" else "10/day",
        "requests_used": 0,
        "created_at": datetime.now().isoformat()
    }
    return {"api_key": api_key, "plan": plan, "message": f"API key created for {plan} plan"}

def check_api_rate_limit(api_key: str) -> tuple:
    """Check if API key has exceeded its rate limit"""
    if api_key not in API_KEYS:
        return False, "Invalid API key"
    
    key_info = API_KEYS[api_key]
    today = datetime.now().strftime("%Y-%m-%d")
    
    # Initialize daily usage for this key
    if api_key not in daily_usage:
        daily_usage[api_key] = {}
    if today not in daily_usage[api_key]:
        daily_usage[api_key][today] = 0
    
    # Get limit based on plan
    limit_map = {
        "free": 10,
        "pro": 1000,
        "business": 10000,
        "enterprise": 100000
    }
    daily_limit = limit_map.get(key_info["plan"], 10)
    
    # Check if over limit
    if daily_usage[api_key][today] >= daily_limit:
        return False, f"Rate limit exceeded ({daily_limit} requests/day). Upgrade your plan at /upgrade"
    
    # Increment usage
    daily_usage[api_key][today] += 1
    
    return True, {"remaining": daily_limit - daily_usage[api_key][today], "limit": daily_limit}

# ==================== RATE LIMITING SETUP ====================
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ==================== TRUSTED DOMAINS (Safety Net) ====================
TRUSTED_DOMAINS = {
    'youtube.com', 'youtu.be', 'facebook.com', 'twitter.com', 
    'instagram.com', 'linkedin.com', 'reddit.com', 'github.com',
    'google.com', 'gmail.com', 'drive.google.com', 'docs.google.com',
    'stackoverflow.com', 'wikipedia.org', 'amazon.com', 'paypal.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
    'zoom.us', 'dropbox.com', 'slack.com', 'discord.com', 'telegram.org'
}

def is_trusted_domain(domain: str) -> bool:
    """Check if domain is in trusted whitelist"""
    domain = domain.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    
    if domain in TRUSTED_DOMAINS:
        return True
    
    parts = domain.split('.')
    for i in range(len(parts)):
        test_domain = '.'.join(parts[i:])
        if test_domain in TRUSTED_DOMAINS:
            return True
    return False

# ==================== LOAD MODEL ====================
print("Loading PhishGuard AI model...")
model = joblib.load('model.pkl')
vectorizer = joblib.load('vectorizer.pkl')
print("✅ Model loaded successfully!")

# ==================== REQUEST/RESPONSE MODELS ====================
class URLRequest(BaseModel):
    url: str
    include_whois: bool = True

class WHOISInfo(BaseModel):
    registrar: Optional[str] = None
    organization: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_new_domain: Optional[bool] = None
    domain_exists: Optional[bool] = None
    error: Optional[str] = None

class URLResponse(BaseModel):
    url: str
    domain: str
    is_phishing: bool
    confidence: float
    status: str
    threat_score: int
    timestamp: str
    request_id: str
    remaining_requests: Optional[int] = None
    whois: Optional[WHOISInfo] = None

class BatchURLRequest(BaseModel):
    urls: list[str]
    include_whois: bool = False

class BatchURLResponse(BaseModel):
    results: list[URLResponse]

# ==================== FEATURE EXTRACTION (13 features) ====================
def extract_features_13(url):
    """Extract exactly 13 features to match model's 2013 total"""
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
    
    # 8. Has HTTPS?
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

# ==================== PREDICTION WITH SAFETY NET ====================
def predict_url_with_safety(url: str):
    """Predict with confidence threshold safety net to prevent false positives"""
    # Extract features
    features = extract_features_13(url)
    
    # Apply TF-IDF
    X_text = vectorizer.transform([url])
    
    # Combine features
    X = hstack([X_text, csr_matrix([features])])
    
    # Get prediction
    prediction = model.predict(X)[0]
    confidence = model.predict_proba(X)[0].max()
    
    # ==================== SAFETY NET ====================
    url_lower = url.lower()
    
    # Known legitimate patterns that might trigger false positives
    false_positive_patterns = [
        'youtube.com/watch', 'youtu.be/', '.com/watch?v=', 'google.com/search',
        'github.com/', 'stackoverflow.com/questions', 'docs.google.com',
        'drive.google.com', 'reddit.com/r/', 'twitter.com/', 'facebook.com/',
        'instagram.com/', 'linkedin.com/in/', 'medium.com/', 'wikipedia.org/wiki/',
        'amazon.com/dp/', 'netflix.com/watch/', 'spotify.com/track/'
    ]
    
    # Check if URL matches any legitimate pattern
    is_likely_false_positive = False
    for pattern in false_positive_patterns:
        if re.search(pattern, url_lower):
            is_likely_false_positive = True
            break
    
    # Also check for known trusted domains
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        if domain in TRUSTED_DOMAINS:
            is_likely_false_positive = True
    except:
        pass
    
    # Apply safety net logic
    if prediction == 1 and is_likely_false_positive:
        old_confidence = confidence
        confidence = confidence * 0.25
        if confidence < 0.5:
            prediction = 0
            confidence = 1 - old_confidence * 0.25
            if confidence > 0.95:
                confidence = 0.95
    
    confidence = max(0.01, min(0.99, confidence))
    
    return bool(prediction), float(confidence)

# ==================== QUICK DOMAIN CHECK ====================
def quick_domain_check(domain: str):
    """Quick DNS check without full WHOIS (faster)"""
    try:
        socket.setdefaulttimeout(3)
        ip = socket.gethostbyname(domain)
        return {"domain_exists": True, "ip": ip}
    except socket.gaierror:
        return {"domain_exists": False, "error": "Domain does not resolve"}
    except Exception as e:
        return {"domain_exists": None, "error": str(e)[:50]}

# ==================== WHOIS LOOKUP WITH TIMEZONE FIX ====================
@lru_cache(maxsize=500)
def get_cached_whois(domain: str):
    """Cached WHOIS lookup with timeout and timezone fix"""
    try:
        dns_check = quick_domain_check(domain)
        
        if not dns_check.get("domain_exists", True):
            return WHOISInfo(
                domain_exists=False,
                error="Domain does not exist or cannot be resolved"
            )
        
        import whois
        w = whois.whois(domain)
        
        # Parse creation date with timezone fix
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            try:
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)
            except:
                pass
        
        # Calculate domain age
        domain_age_days = None
        is_new_domain = None
        if creation_date:
            try:
                now = datetime.now()
                if hasattr(now, 'tzinfo') and now.tzinfo is not None:
                    now = now.replace(tzinfo=None)
                domain_age_days = (now - creation_date).days
                is_new_domain = domain_age_days < 30
            except:
                domain_age_days = None
                is_new_domain = None
        
        # Parse expiration date with same fix
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date and hasattr(expiration_date, 'tzinfo') and expiration_date.tzinfo is not None:
            expiration_date = expiration_date.replace(tzinfo=None)
        
        # Parse updated date with same fix
        updated_date = w.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
        if updated_date and hasattr(updated_date, 'tzinfo') and updated_date.tzinfo is not None:
            updated_date = updated_date.replace(tzinfo=None)
        
        return WHOISInfo(
            registrar=str(w.registrar)[:100] if w.registrar else None,
            organization=str(w.org)[:100] if w.org else None,
            creation_date=str(creation_date) if creation_date else None,
            expiration_date=str(expiration_date) if expiration_date else None,
            updated_date=str(updated_date) if updated_date else None,
            domain_age_days=domain_age_days,
            is_new_domain=is_new_domain,
            domain_exists=True,
            error=None
        )
    except Exception as e:
        error_msg = str(e)[:100]
        if "offset-naive" in error_msg or "offset-aware" in error_msg:
            error_msg = "WHOIS timezone issue - domain exists but date parsing failed"
        return WHOISInfo(
            domain_exists=None,
            error=f"WHOIS lookup failed: {error_msg}"
        )

async def get_whois_with_timeout(domain: str, timeout_seconds: int = 8):
    """Async WHOIS lookup with timeout"""
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(executor, get_cached_whois, domain),
            timeout=timeout_seconds
        )
        return result
    except asyncio.TimeoutError:
        return WHOISInfo(
            domain_exists=None,
            error="WHOIS lookup timed out"
        )
    except Exception as e:
        return WHOISInfo(
            domain_exists=None,
            error=f"WHOIS error: {str(e)[:50]}"
        )

# ==================== API KEY VALIDATION DEPENDENCY ====================
async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API key and check rate limits"""
    api_key = credentials.credentials
    
    # Check if API key exists
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Check rate limit
    is_valid, result = check_api_rate_limit(api_key)
    if not is_valid:
        raise HTTPException(status_code=429, detail=result)
    
    # Get remaining requests
    today = datetime.now().strftime("%Y-%m-%d")
    remaining = None
    if api_key in daily_usage and today in daily_usage[api_key]:
        limit_map = {"free": 10, "pro": 1000, "business": 10000, "enterprise": 100000}
        daily_limit = limit_map.get(API_KEYS[api_key]["plan"], 10)
        remaining = daily_limit - daily_usage[api_key][today]
    
    return {"api_key": api_key, "plan": API_KEYS[api_key]["plan"], "remaining": remaining}

# ==================== API ENDPOINTS ====================
@app.get("/")
async def root():
    return {
        "service": "PhishGuard Pro",
        "version": "2.0.0",
        "status": "operational",
        "features": ["AI Detection", "WHOIS Intelligence", "DNS Check", "False Positive Protection", "API Key Auth", "Rate Limiting"],
        "endpoints": ["/predict", "/batch-predict", "/health", "/check-domain", "/generate-api-key", "/upgrade"],
        "pricing": {
            "free": {"requests": "10/day", "price": "$0"},
            "pro": {"requests": "1000/day", "price": "$9/month"},
            "business": {"requests": "10000/day", "price": "$49/month"},
            "enterprise": {"requests": "Unlimited", "price": "$199/month"}
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "model_loaded": True,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/generate-api-key")
async def generate_free_api_key(plan: str = "free"):
    """Generate a new free API key"""
    if plan not in ["free", "pro", "business", "enterprise"]:
        plan = "free"
    result = generate_api_key(plan)
    return result

@app.post("/upgrade")
async def upgrade_plan(api_key: str, plan: str):
    """Upgrade API key plan (in production, this would integrate with Stripe)"""
    if api_key not in API_KEYS:
        raise HTTPException(status_code=404, detail="API key not found")
    
    if plan not in ["pro", "business", "enterprise"]:
        raise HTTPException(status_code=400, detail="Invalid plan. Choose: pro, business, enterprise")
    
    # In production, verify payment here
    # For demo, just upgrade
    API_KEYS[api_key]["plan"] = plan
    limit_map = {"pro": "1000/day", "business": "10000/day", "enterprise": "100000/day"}
    API_KEYS[api_key]["rate_limit"] = limit_map.get(plan, "1000/day")
    
    return {
        "message": f"Successfully upgraded to {plan} plan",
        "api_key": api_key,
        "plan": plan,
        "rate_limit": API_KEYS[api_key]["rate_limit"]
    }

@app.get("/check-domain")
async def check_domain_only(domain: str):
    """Quick domain existence check"""
    return quick_domain_check(domain)

@app.post("/predict", response_model=URLResponse)
async def predict_single(
    request: URLRequest,
    api_key_info: dict = Depends(verify_api_key)
):
    """Check if a single URL is phishing (with optional WHOIS)"""
    try:
        # Extract domain
        try:
            parsed = urlparse(request.url)
            domain = parsed.netloc or parsed.path
            domain = domain.split('/')[0]
            domain = domain.split(':')[0]
        except:
            domain = request.url
        
        # ==================== TRUSTED DOMAIN CHECK ====================
        if is_trusted_domain(domain):
            return URLResponse(
                url=request.url,
                domain=domain,
                is_phishing=False,
                confidence=0.97,
                status="safe",
                threat_score=3,
                timestamp=datetime.now().isoformat(),
                request_id=str(uuid.uuid4())[:8],
                remaining_requests=api_key_info.get("remaining"),
                whois=await get_whois_with_timeout(domain, timeout_seconds=5) if request.include_whois and api_key_info["plan"] != "free" else None
            )
        
        # ==================== AI PREDICTION WITH SAFETY NET ====================
        is_phishing, confidence = predict_url_with_safety(request.url)
        
        # Calculate threat score
        if is_phishing:
            threat_score = int(confidence * 100)
        else:
            threat_score = int((1 - confidence) * 100)
        
        threat_score = max(0, min(100, threat_score))
        
        # Get WHOIS if requested (only for paid plans)
        whois_info = None
        if request.include_whois and api_key_info["plan"] != "free":
            try:
                whois_info = await get_whois_with_timeout(domain, timeout_seconds=8)
                
                if whois_info and whois_info.domain_exists is False:
                    is_phishing = True
                    confidence = max(confidence, 0.85)
                    threat_score = 85
                elif whois_info and whois_info.is_new_domain and not is_phishing:
                    confidence = confidence * 0.7
                    threat_score = int((1 - confidence) * 100)
            except Exception:
                whois_info = WHOISInfo(error="WHOIS unavailable")
        
        return URLResponse(
            url=request.url,
            domain=domain,
            is_phishing=is_phishing,
            confidence=round(confidence, 4),
            status="malicious" if is_phishing else "safe",
            threat_score=threat_score,
            timestamp=datetime.now().isoformat(),
            request_id=str(uuid.uuid4())[:8],
            remaining_requests=api_key_info.get("remaining"),
            whois=whois_info
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing URL: {str(e)}")

@app.post("/batch-predict", response_model=BatchURLResponse)
async def predict_batch(
    request: BatchURLRequest,
    api_key_info: dict = Depends(verify_api_key)
):
    """Check multiple URLs for phishing (max 50 at a time)"""
    if len(request.urls) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 URLs per batch request")
    
    results = []
    for url in request.urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            domain = domain.split('/')[0]
            domain = domain.split(':')[0]
            
            # Check trusted domains first
            if is_trusted_domain(domain):
                results.append(URLResponse(
                    url=url,
                    domain=domain,
                    is_phishing=False,
                    confidence=0.97,
                    status="safe",
                    threat_score=3,
                    timestamp=datetime.now().isoformat(),
                    request_id=str(uuid.uuid4())[:8],
                    remaining_requests=api_key_info.get("remaining"),
                    whois=None
                ))
                continue
            
            # AI prediction with safety net
            is_phishing, confidence = predict_url_with_safety(url)
            threat_score = int(confidence * 100) if is_phishing else int((1 - confidence) * 100)
            threat_score = max(0, min(100, threat_score))
            
            whois_info = None
            if request.include_whois and api_key_info["plan"] != "free":
                whois_info = await get_whois_with_timeout(domain, timeout_seconds=5)
            
            results.append(URLResponse(
                url=url,
                domain=domain,
                is_phishing=is_phishing,
                confidence=round(confidence, 4),
                status="malicious" if is_phishing else "safe",
                threat_score=threat_score,
                timestamp=datetime.now().isoformat(),
                request_id=str(uuid.uuid4())[:8],
                remaining_requests=api_key_info.get("remaining"),
                whois=whois_info
            ))
        except Exception as e:
            results.append(URLResponse(
                url=url,
                domain=domain if 'domain' in locals() else url,
                is_phishing=False,
                confidence=0.0,
                status="error",
                threat_score=0,
                timestamp=datetime.now().isoformat(),
                request_id=str(uuid.uuid4())[:8],
                remaining_requests=api_key_info.get("remaining"),
                whois=WHOISInfo(error=f"Error: {str(e)[:50]}")
            ))
    
    return BatchURLResponse(results=results)

@app.post("/create-subscription")
async def create_subscription(plan: str, api_key: str):
    """Create Stripe checkout session (integration ready)"""
    # Prices in cents
    prices = {
        "pro": 900,      # $9.00
        "business": 4900, # $49.00
        "enterprise": 19900 # $199.00
    }
    
    if plan not in prices:
        raise HTTPException(status_code=400, detail="Invalid plan")
    
    # In production, integrate with Stripe:
    # import stripe
    # stripe.api_key = "your_stripe_secret_key"
    # checkout_session = stripe.checkout.Session.create(...)
    
    # For demo, return mock URL
    return {
        "checkout_url": f"https://checkout.stripe.com/mock/{plan}",
        "amount": prices[plan],
        "currency": "usd",
        "api_key": api_key,
        "message": "In production, this would redirect to Stripe checkout"
    }

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook for subscription updates"""
    # In production, verify webhook signature and update API key plan
    # body = await request.body()
    # event = stripe.Webhook.construct_event(...)
    
    return {"status": "received"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
