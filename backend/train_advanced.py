import pandas as pd
import joblib
import time
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "Aligned_URL_Dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")

print("=" * 70)
print("      ADVANCED BEHAVIORAL ML MODEL TRAINING ")
print("=" * 70)

if not os.path.exists(CSV_PATH):
    print(f"\n[-] Error: Dataset not found at {CSV_PATH}!")
    exit(1)

print("\nLoading advanced dataset...")
df = pd.read_csv(CSV_PATH)
print(f"Dataset Shape : {df.shape}")

# Automatically drop all string/object columns (like URL, Domain, Title, etc.)
df = df.select_dtypes(exclude=['object'])

# The dataset has 1=Legitimate and 0=Phishing. 
# We invert it so 1=Phishing and 0=Legitimate to match standard convention and app.py
df['label'] = 1 - df['label']

SAFE_FEATURES = [
    "IsHTTPS", "DomainLength", "SubDomainLength", "IsHighAuthority",
    "NoOfDegitsInURL", "LetterRatioInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "HasPunycode", "IsCloudOrDynamicDNS", "URLSimilarityIndex",
    "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "HasDescription", "HasFavicon", "HasTitle", "HasCopyrightInfo",
    "NoOfPopup", "NoOfiFrame", "IsResponsive", "NoOfImage",
    "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    "HasBankDataFields", "HasSuspiciousFormAction",
    "label"
]

# Only keep features that exist in the dataframe and are in SAFE_FEATURES
existing_safe_features = [f for f in SAFE_FEATURES if f in df.columns]
df = df[existing_safe_features]

# Ensure no NaNs from missing values
df = df.fillna(0)

# Features & Labels
X = df.drop("label", axis=1)
y = df["label"]

print(f"\nNumber of Features: {X.shape[1]}")

# Train Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print("\nTraining Random Forest Model...")
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)

start = time.time()
model.fit(X_train, y_train)
end = time.time()

print(f"Training Time : {end-start:.2f} seconds")

# Predict and Evaluate
pred = model.predict(X_test)
accuracy = accuracy_score(y_test, pred)

print("\n" + "=" * 70)
print(f"Accuracy : {accuracy:.4f}")
print("=" * 70)

print("\nClassification Report\n")
print(classification_report(y_test, pred, target_names=["Legitimate", "Phishing"]))

# Save Model
os.makedirs(MODEL_DIR, exist_ok=True)
model_path = os.path.join(MODEL_DIR, "advanced_rf_model.pkl")
features_path = os.path.join(MODEL_DIR, "advanced_feature_names.pkl")

joblib.dump(model, model_path)
joblib.dump(list(X.columns), features_path)

print(f"\n[+] Advanced Model Saved Successfully to: {model_path}")

# Feature Importance
importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
}).sort_values(by="Importance", ascending=False)

print("\nTop 15 Most Important Features (Look for the new ones!)\n")
print(importance.head(15))
