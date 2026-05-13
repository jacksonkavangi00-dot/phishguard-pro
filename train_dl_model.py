import pandas as pd
import numpy as np
import os
import joblib

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ================= LOAD DATA =================
def load_file(path, label):
    try:
        df = pd.read_csv(path, on_bad_lines='skip')

        if "url" not in df.columns:
            df = df.iloc[:, 0].to_frame(name="url")

        df["label"] = label
        return df

    except:
        return None


dataframes = []

files = [
    ("safe_real_big.csv", 0),
    ("phishing_urls_final.csv", 1),
]

for file, label in files:
    path = os.path.join(BASE_DIR, file)
    df = load_file(path, label)
    if df is not None:
        dataframes.append(df)

df = pd.concat(dataframes)

# ================= CLEAN =================
df = df.dropna(subset=["url"])
df["url"] = df["url"].astype(str)

# ================= BALANCE =================
df_safe = df[df["label"] == 0].sample(200000, random_state=42)
df_phish = df[df["label"] == 1].sample(200000, random_state=42)

df = pd.concat([df_safe, df_phish])

# ================= TOKENIZE =================
tokenizer = Tokenizer(char_level=True)
tokenizer.fit_on_texts(df["url"])

X = tokenizer.texts_to_sequences(df["url"])
X = pad_sequences(X, maxlen=100)

y = df["label"].values

# ================= SPLIT =================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ================= MODEL =================
model = Sequential([
    Embedding(input_dim=100, output_dim=32, input_length=100),
    LSTM(64),
    Dense(32, activation="relu"),
    Dense(1, activation="sigmoid")
])

model.compile(
    loss="binary_crossentropy",
    optimizer="adam",
    metrics=["accuracy"]
)

# ================= TRAIN =================
model.fit(X_train, y_train, epochs=3, batch_size=256)

# ================= SAVE =================
model.save(os.path.join(BASE_DIR, "dl_model.h5"))
joblib.dump(tokenizer, os.path.join(BASE_DIR, "tokenizer.pkl"))

print("Deep learning model trained ✔")
