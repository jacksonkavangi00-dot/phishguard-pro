from urllib.parse import urlparse
import re

# 🔥 Known brand targets
BRANDS = ["paypal", "google", "facebook", "bank", "apple", "amazon", "microsoft"]

def extract_features(url):
    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    url_lower = url.lower()

    return [
        len(url),                                  # 1 URL length
        len(domain),                               # 2 domain length
        url.count('-'),                            # 3 hyphens
        url.count('@'),                            # 4 @ symbol
        url.count('?'),                            # 5 query symbols
        url.count('='),                            # 6 equals
        url.count('.'),                            # 7 dots
        int(url.startswith('https')),              # 8 HTTPS (safe signal)

        # 🔥 STRONG SIGNALS
        int('login' in url_lower),                 # 9
        int('verify' in url_lower),                # 10
        int('update' in url_lower),                # 11
        int('secure' in url_lower),                # 12

        # 🔥 BRAND IMPERSONATION
        int(any(b in domain for b in BRANDS)),     # 13

        # 🔥 SUSPICIOUS STRUCTURE
        int(len(domain.split('.')) > 3),           # 14 many subdomains
        int(domain.count('-') > 1),                # 15 many hyphens
        int(bool(re.search(r'\d', domain))),       # 16 numbers in domain

        # 🔥 CRITICAL FLAG
        int(url.startswith('http://')),            # 17 no HTTPS = risky
    ]
