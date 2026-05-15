import pandas as pd
import numpy as np
from urllib.parse import urlparse

print("🔍 Building improved dataset with diverse URLs...")

# ==================== LOAD EXISTING DATA ====================
print("\n📂 Loading existing data...")

# Safe URLs from Cisco Umbrella (good base)
safe_df = pd.read_csv('top-1m.csv', header=None)
safe_df.columns = ['rank', 'domain']
safe_df['url'] = 'https://' + safe_df['domain']
safe_df['label'] = 0
print(f"✅ Loaded {len(safe_df)} base safe URLs")

# ==================== ADD DIVERSE SAFE URLS ====================
print("\n🌐 Adding diverse safe URLs...")

# Common web patterns (these were causing false positives)
diverse_safe_urls = [
    # YouTube patterns
    'https://youtube.com/watch?v=123456789',
    'https://youtu.be/abc123def',
    'https://youtube.com/shorts/abc123',
    'https://m.youtube.com/watch?v=xyz789',
    'https://youtube.com/playlist?list=PL123456',
    'https://www.youtube.com/results?search_query=test',
    
    # Google patterns
    'https://google.com/search?q=test+query',
    'https://google.com/maps/place/London',
    'https://docs.google.com/document/d/123/edit',
    'https://drive.google.com/file/d/456/view',
    'https://mail.google.com/mail/u/0/#inbox',
    
    # GitHub patterns
    'https://github.com/user/repo/issues/1',
    'https://github.com/user/repo/pull/2',
    'https://raw.githubusercontent.com/user/repo/main/file.py',
    'https://gist.github.com/user/123456',
    
    # Stack Overflow
    'https://stackoverflow.com/questions/123/test',
    'https://stackoverflow.com/users/456/user',
    
    # Social media patterns
    'https://twitter.com/user/status/123456789',
    'https://reddit.com/r/subreddit/comments/123/test',
    'https://linkedin.com/in/username',
    'https://instagram.com/p/ABC123',
    
    # Long URLs with many parameters
    'https://example.com/page?param1=value1&param2=value2&param3=value3&param4=value4',
    'https://blog.example.com/2024/01/01/very-long-article-title-with-many-hyphens',
    'https://shop.example.com/category/subcategory/product?ref=123&utm_source=google',
]

for url in diverse_safe_urls:
    safe_df = pd.concat([safe_df, pd.DataFrame({'url': [url], 'label': [0]})], ignore_index=True)

print(f"✅ Added {len(diverse_safe_urls)} diverse safe URLs")

# ==================== LOAD PHISHING DATA ====================
print("\n⚠️ Loading phishing data...")

try:
    phish_df = pd.read_csv('phishing_urls_real.csv')
    if 'url' in phish_df.columns:
        phish_df = phish_df[['url']].copy()
    else:
        phish_df = phish_df.iloc[:, [0]].copy()
        phish_df.columns = ['url']
    phish_df['label'] = 1
    print(f"✅ Loaded {len(phish_df)} phishing URLs")
except Exception as e:
    print(f"⚠️ Could not load phishing data: {e}")
    phish_df = pd.DataFrame()

# ==================== BALANCE DATASET ====================
print("\n⚖️ Balancing dataset...")

# Take 50k safe, 50k phishing for training
safe_sample = safe_df.sample(n=min(50000, len(safe_df)), random_state=42)
phish_sample = phish_df.sample(n=min(50000, len(phish_df)), random_state=42) if len(phish_df) > 0 else pd.DataFrame()

combined_df = pd.concat([safe_sample, phish_sample], ignore_index=True)
combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle

print(f"✅ Final dataset: {len(combined_df)} URLs ({len(safe_sample)} safe, {len(phish_sample)} phishing)")

# ==================== SAVE ====================
combined_df.to_csv('improved_training_data.csv', index=False)
print("\n💾 Saved to 'improved_training_data.csv'")
print("\n📊 Sample URLs:")
for i in range(min(5, len(combined_df))):
    print(f"  {combined_df['url'].iloc[i][:80]}... ({'SAFE' if combined_df['label'].iloc[i]==0 else 'PHISHING'})")
