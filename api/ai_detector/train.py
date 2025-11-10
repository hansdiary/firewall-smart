# train.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# === 1️⃣ Charger le dataset ===
df = pd.read_csv("network_dataset_ready.csv")

# === 2️⃣ Préparer les features et labels ===
FEATURES = ["ip_num", "port", "proto", "length"]
X = df[FEATURES]
y = df["is_malicious"]

# === 3️⃣ Split train/test ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# === 4️⃣ Créer le modèle ===
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    random_state=42,
    class_weight="balanced"
)

# === 5️⃣ Entraîner le modèle ===
model.fit(X_train, y_train)

# === 6️⃣ Évaluer le modèle ===
y_pred = model.predict(X_test)
print("=== Classification Report ===")
print(classification_report(y_test, y_pred))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

# === 7️⃣ Sauvegarder le modèle ===
joblib.dump(model, "api/ai_detector/model.pkl")
print("✅ Modèle sauvegardé dans 'model.pkl'")
