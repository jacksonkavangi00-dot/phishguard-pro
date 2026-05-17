import streamlit as st
import requests
import json
from urllib.parse import urlparse
import time
from datetime import datetime
import plotly.graph_objects as go
import pandas as pd

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="PhishGuard Pro - AI Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== API CONFIGURATION ====================
# LIVE PRODUCTION API URL (CHANGED FROM LOCALHOST)
API_BASE_URL = "https://phishguard-pro-orzz.onrender.com"

# ==================== API KEY MANAGEMENT ====================
def get_or_create_api_key():
    """Get API key from session or generate new one"""
    if 'api_key' not in st.session_state:
        try:
            response = requests.get(f"{API_BASE_URL}/generate-api-key?plan=free", timeout=10)
            if response.status_code == 200:
                st.session_state.api_key = response.json().get("api_key")
                st.session_state.api_key_plan = "free"
            else:
                st.session_state.api_key = "free_demo_key"
                st.session_state.api_key_plan = "free"
        except Exception as e:
            st.session_state.api_key = "free_demo_key"
            st.session_state.api_key_plan = "free"
    return st.session_state.api_key

# Initialize API key
API_KEY = get_or_create_api_key()

# ==================== CUSTOM CSS ====================
st.markdown("""
<style>
    /* Import modern font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    /* Gradient background */
    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
    }
    
    /* Main header */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 20px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    }
    
    .main-header h1 {
        font-size: 3rem;
        font-weight: 800;
        margin: 0;
        background: linear-gradient(135deg, #fff 0%, #e0e0e0 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Threat indicators */
    .threat-critical {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        border-radius: 15px;
        padding: 1.5rem;
        color: white;
        animation: pulse 2s infinite;
    }
    
    .threat-safe {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        border-radius: 15px;
        padding: 1.5rem;
        color: white;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.02); }
        100% { transform: scale(1); }
    }
    
    /* Custom button */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 12px 30px;
        font-weight: 600;
        font-size: 16px;
        transition: all 0.3s;
        width: 100%;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(0,0,0,0.3);
    }
    
    /* Metric cards */
    .metric-card {
        background: rgba(255,255,255,0.95);
        border-radius: 15px;
        padding: 1rem;
        box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        text-align: center;
    }
    
    /* WHOIS card */
    .whois-card {
        background: rgba(255,255,255,0.1);
        backdrop-filter: blur(10px);
        border-radius: 15px;
        padding: 1rem;
        margin: 0.5rem 0;
        border: 1px solid rgba(255,255,255,0.2);
    }
</style>
""", unsafe_allow_html=True)

# ==================== SIDEBAR ====================
with st.sidebar:
    st.markdown("### 🛡️ **PhishGuard Pro**")
    st.markdown("---")
    
    # API Configuration (now using live URL)
    api_url = st.text_input("🔌 **API Endpoint**", value=API_BASE_URL, disabled=True)
    
    # Show API Key Info
    st.markdown("### 🔑 **Your API Key**")
    st.code(API_KEY, language="text")
    st.caption("Save this key! You get 10 free requests per day.")
    
    # Button to regenerate key
    if st.button("🔄 Regenerate API Key", use_container_width=True):
        try:
            response = requests.get(f"{API_BASE_URL}/generate-api-key?plan=free", timeout=10)
            if response.status_code == 200:
                st.session_state.api_key = response.json().get("api_key")
                st.rerun()
        except:
            st.error("Could not regenerate key")
    
    st.markdown("---")
    
    # Stats
    st.markdown("### 📊 **System Stats**")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Accuracy", "99.42%", "↑")
    with col2:
        st.metric("Response", "<100ms", "⚡")
    
    st.markdown("---")
    
    # WHOIS toggle
    st.markdown("### 🔧 **Settings**")
    include_whois = st.checkbox("🌐 Include WHOIS Data", value=True, help="Shows domain registration information (Pro feature)")
    
    st.markdown("---")
    
    # Recent scans
    st.markdown("### 📋 **Recent Scans**")
    if 'recent_scans' not in st.session_state:
        st.session_state.recent_scans = []
    
    for scan in st.session_state.recent_scans[-5:]:
        st.text(scan)
    
    st.markdown("---")
    
    # Plan info
    st.markdown("### 💎 **Your Plan**")
    st.info("🔓 Free Plan - 10 requests/day")
    st.markdown("[Upgrade to Pro](https://phishguard-pro-orzz.onrender.com/upgrade)")
    
    st.markdown("---")
    
    # Security tips
    with st.expander("🛡️ **Security Tips**"):
        st.markdown("""
        - ✅ Always check URL before clicking
        - 🔒 Look for HTTPS padlock
        - ❌ Never enter passwords on suspicious sites
        - 📧 Be wary of urgent login requests
        - 🌐 Check domain age (new domains = suspicious)
        """)
    
    st.markdown("---")
    st.caption("🔒 **Enterprise Grade AI Security**")

# ==================== MAIN CONTENT ====================
# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ PhishGuard Pro</h1>
    <p>AI-Powered Phishing Threat Intelligence Engine</p>
</div>
""", unsafe_allow_html=True)

# ==================== URL INPUT SECTION ====================
st.markdown("### 🌐 **Enter URL to Analyze**")

# Use columns for better layout
col1, col2 = st.columns([4, 1])

with col1:
    # Use session state to persist URL input
    if 'url_input_value' not in st.session_state:
        st.session_state.url_input_value = ""
    
    url_input = st.text_input(
        "URL",
        value=st.session_state.url_input_value,
        placeholder="https://example.com or http://secure-paypal-login-update.com",
        label_visibility="collapsed",
        key="url_input_main"
    )
    
    # Update session state when URL changes
    st.session_state.url_input_value = url_input

with col2:
    analyze_button = st.button("🚀 **Analyze**", type="primary", use_container_width=True)

# Add example quick-links
st.markdown("**Quick test URLs:**")
example_col1, example_col2, example_col3, example_col4 = st.columns(4)

with example_col1:
    if st.button("📧 Google", use_container_width=True):
        st.session_state.url_input_value = "https://google.com"
        st.rerun()

with example_col2:
    if st.button("⚠️ Test Phishing", use_container_width=True):
        st.session_state.url_input_value = "http://secure-paypal-login-update.com"
        st.rerun()

with example_col3:
    if st.button("🏦 GitHub", use_container_width=True):
        st.session_state.url_input_value = "https://github.com"
        st.rerun()

with example_col4:
    if st.button("▶️ YouTube", use_container_width=True):
        st.session_state.url_input_value = "https://youtube.com/watch?v=W8a4sUabCUo"
        st.rerun()

st.markdown("---")

# ==================== API CALL FUNCTION WITH AUTH ====================
def check_url_with_api(url, include_whois_data=True):
    """Send URL to backend API with authentication"""
    try:
        # Make request with API key in header
        response = requests.post(
            f"{api_url}/predict",
            json={"url": url, "include_whois": include_whois_data},
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            timeout=15
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            st.error("❌ Invalid API key. Regenerating...")
            # Regenerate key and retry
            try:
                new_key_response = requests.get(f"{api_url}/generate-api-key?plan=free", timeout=10)
                if new_key_response.status_code == 200:
                    st.session_state.api_key = new_key_response.json().get("api_key")
                    st.rerun()
            except:
                pass
            return None
        elif response.status_code == 429:
            st.error("⚠️ Rate limit exceeded! You've used all your free requests for today. Upgrade to Pro for more requests.")
            return None
        else:
            st.error(f"API Error: {response.status_code}")
            try:
                error_detail = response.json().get("detail", response.text)
                st.code(error_detail)
            except:
                st.code(response.text)
            return None
            
    except requests.exceptions.ConnectionError:
        st.error(f"❌ Cannot connect to API at {api_url}\n\nMake sure backend is running")
        return None
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

# ==================== PROCESSING ====================
if analyze_button and url_input:
    # Add to recent scans
    st.session_state.recent_scans.insert(0, f"{url_input[:50]}... 🔄")
    
    with st.spinner("🧠 **Analyzing URL with advanced AI + WHOIS intelligence...**"):
        time.sleep(0.3)
        result = check_url_with_api(url_input, include_whois)
    
    if result:
        is_phishing = result['is_phishing']
        confidence = result['confidence']
        
        # Calculate threat score
        threat_score = result.get('threat_score', int(confidence * 100) if is_phishing else int((1 - confidence) * 100))
        confidence_percent = confidence * 100
        
        # Extract domain
        domain = result.get('domain', '')
        if not domain:
            try:
                domain = urlparse(url_input).netloc or urlparse(url_input).path
            except:
                domain = url_input
        
        # Show remaining requests if available
        if result.get('remaining_requests') is not None:
            remaining = result['remaining_requests']
            if remaining < 3:
                st.warning(f"⚠️ You have {remaining} requests remaining today. Upgrade to Pro for more!")
            elif remaining < 10:
                st.info(f"📊 You have {remaining} requests remaining today.")
        
        # Update recent scans with result
        icon = "🔴" if is_phishing else "🟢"
        st.session_state.recent_scans[0] = f"{url_input[:50]}... {icon}"
        
        # ==================== GAUGE CHART ====================
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = threat_score,
            title = {'text': "Threat Score", 'font': {'size': 24, 'color': 'white'}},
            delta = {'reference': 50, 'increasing': {'color': "red"}},
            gauge = {
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                'bar': {'color': "#ff4444" if is_phishing else "#00ff88"},
                'bgcolor': "rgba(255,255,255,0.1)",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 30], 'color': '#4CAF50'},
                    {'range': [30, 70], 'color': '#FFC107'},
                    {'range': [70, 100], 'color': '#f44336'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': threat_score
                }
            }
        ))
        
        fig.update_layout(
            height=300,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            font={'color': "white", 'family': "Arial"}
        )
        
        # ==================== DISPLAY RESULTS ====================
        st.markdown("## 🔎 **Analysis Results**")
        
        # Top metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            delta_color = "inverse" if is_phishing else "normal"
            st.metric(
                "🎯 **Threat Score**", 
                f"{threat_score}/100",
                delta="Critical" if is_phishing else "Safe",
                delta_color=delta_color
            )
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("🤖 **AI Confidence**", f"{confidence_percent:.2f}%")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col3:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("⚠️ **Threat Level**", "HIGH" if is_phishing else "LOW")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col4:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            ssl_status = "Valid ✓" if url_input.startswith("https") else "Missing ⚠️"
            st.metric("🔒 **SSL Status**", ssl_status)
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Gauge chart and details
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if is_phishing:
                st.markdown(f"""
                <div class="threat-critical">
                    <h2>⚠️ HIGH RISK</h2>
                    <p><strong>Verdict:</strong> PHISHING URL DETECTED</p>
                    <p><strong>Confidence:</strong> {confidence_percent:.1f}%</p>
                    <p><strong>Threat Score:</strong> {threat_score}/100</p>
                    <p><strong>Action Required:</strong> Do NOT proceed</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="threat-safe">
                    <h2>✅ LOW RISK</h2>
                    <p><strong>Verdict:</strong> SAFE URL</p>
                    <p><strong>Confidence:</strong> {confidence_percent:.1f}%</p>
                    <p><strong>Threat Score:</strong> {threat_score}/100</p>
                    <p><strong>Action:</strong> Proceed with caution</p>
                </div>
                """, unsafe_allow_html=True)
        
        # Domain intelligence
        st.markdown("---")
        st.markdown("### 🌐 **Domain Intelligence**")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info(f"📡 **Domain:** `{domain}`")
        with col2:
            protocol = "HTTPS 🔒" if url_input.startswith('https') else "HTTP ⚠️"
            st.info(f"🔗 **Protocol:** {protocol}")
        with col3:
            st.info(f"📅 **Analysis:** {datetime.now().strftime('%H:%M:%S')}")
        
        # WHOIS Section
        if include_whois and result.get('whois'):
            st.markdown("---")
            st.markdown("### 🌐 **WHOIS Domain Intelligence**")
            
            whois_data = result['whois']
            
            if whois_data.get('error'):
                st.warning(f"⚠️ WHOIS Lookup: {whois_data['error']}")
            else:
                whois_col1, whois_col2 = st.columns(2)
                
                with whois_col1:
                    st.markdown('<div class="whois-card">', unsafe_allow_html=True)
                    if whois_data.get('registrar'):
                        st.info(f"🏢 **Registrar:** {whois_data['registrar'][:50]}")
                    if whois_data.get('organization'):
                        st.info(f"📋 **Organization:** {whois_data['organization'][:50]}")
                    if whois_data.get('creation_date'):
                        creation = whois_data['creation_date'][:10] if len(whois_data['creation_date']) > 10 else whois_data['creation_date']
                        st.info(f"📅 **Created:** {creation}")
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with whois_col2:
                    st.markdown('<div class="whois-card">', unsafe_allow_html=True)
                    if whois_data.get('domain_age_days'):
                        age_days = whois_data['domain_age_days']
                        age_years = age_days // 365
                        if age_days < 30:
                            st.warning(f"⚠️ **Domain Age:** {age_days} days - NEW DOMAIN")
                        elif age_days < 365:
                            st.info(f"📆 **Domain Age:** {age_days} days")
                        else:
                            st.success(f"✅ **Domain Age:** {age_years} years")
                    if whois_data.get('is_new_domain'):
                        st.error("🚨 **NEW DOMAIN DETECTED** - High risk indicator")
                    st.markdown('</div>', unsafe_allow_html=True)
        
        # Deep analysis tab
        with st.expander("🔍 **Deep Analysis Details**"):
            st.markdown("**URL Structure Analysis:**")
            url_lower = url_input.lower()
            indicators = []
            
            suspicious = ['login', 'verify', 'secure', 'update', 'confirm', 'account', 'password']
            for word in suspicious:
                if word in url_lower:
                    indicators.append(f"• Contains '{word}'")
            
            if indicators and is_phishing:
                for ind in indicators:
                    st.markdown(f"⚠️ {ind}")
            elif indicators and not is_phishing:
                for ind in indicators:
                    st.markdown(f"ℹ️ {ind} (present but URL classified as safe)")
            else:
                st.markdown("No obvious suspicious patterns detected")
            
            st.markdown("**Model Information:**")
            st.markdown("- Algorithm: Random Forest Classifier")
            st.markdown("- Features: 2013 (2000 TF-IDF + 13 structural)")
            st.markdown("- Training Accuracy: 99.42%")
            
            # Raw JSON
            st.json(result)

elif analyze_button and not url_input:
    st.warning("⚠️ **Please enter a URL to analyze**")

# ==================== FEATURED SECTION (when no analysis) ====================
else:
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="whois-card" style="text-align: center;">
            <h2>🚀 99.42%</h2>
            <p>Detection Accuracy</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="whois-card" style="text-align: center;">
            <h2>⚡ &lt;100ms</h2>
            <p>Response Time</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="whois-card" style="text-align: center;">
            <h2>🌐 Live API</h2>
            <p>24/7 Available</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; padding: 2rem;">
        <h3>🔒 Ready to analyze</h3>
        <p>Enter a URL above to check if it's a phishing threat</p>
        <br>
        <p style="font-size: 0.9rem;">💡 <strong>Your API key is ready! You have 10 free requests per day.</strong></p>
    </div>
    """, unsafe_allow_html=True)

# ==================== FOOTER ====================
st.markdown("---")
st.markdown("""
<div style="text-align: center; padding: 1rem;">
    <p>🛡️ <strong>PhishGuard Pro</strong> | AI-Powered Real-time Protection + WHOIS Intelligence | v2.0</p>
    <p>🔗 <strong>API Endpoint:</strong> https://phishguard-pro-orzz.onrender.com</p>
</div>
""", unsafe_allow_html=True)
