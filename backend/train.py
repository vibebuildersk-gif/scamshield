import time
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

print("=" * 70)
print("        PHISHING URL DETECTION MODEL TRAINING")
print("=" * 70)

# ==========================================================
# Load Dataset
# ==========================================================

print("\nLoading dataset...")

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

print(f"Original Dataset Shape : {df.shape}")

# ==========================================================
# Remove Missing Values
# ==========================================================

df = df.dropna()

# ==========================================================
# Remove Duplicate URLs
# ==========================================================

df = df.drop_duplicates(subset=["URL"])

print(f"Dataset After Removing Duplicates : {df.shape}")

# ==========================================================
# Remove Text Columns
# ==========================================================

drop_columns = [
    "FILENAME",
    "URL",
    "Domain",
    "Title",
    "TLD"
]

df = df.drop(columns=drop_columns)

print(f"Training Dataset Shape : {df.shape}")

# ==========================================================
# Features & Labels
# ==========================================================

X = df.drop("label", axis=1)
y = df["label"]

print(f"\nNumber of Features : {X.shape[1]}")

# ==========================================================
# Train Test Split
# ==========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training Samples : {len(X_train)}")
print(f"Testing Samples  : {len(X_test)}")

# ==========================================================
# Random Forest Model
# ==========================================================

print("\nTraining Random Forest Model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)

start = time.time()

model.fit(X_train, y_train)

end = time.time()

print(f"Training Time : {end-start:.2f} seconds")

# ==========================================================
# Prediction
# ==========================================================

pred = model.predict(X_test)

# ==========================================================
# Accuracy
# ==========================================================

accuracy = accuracy_score(y_test, pred)

print("\n" + "=" * 70)
print(f"Accuracy : {accuracy:.4f}")
print("=" * 70)

# ==========================================================
# Confusion Matrix
# ==========================================================

print("\nConfusion Matrix\n")

print(confusion_matrix(y_test, pred))

# ==========================================================
# Classification Report
# ==========================================================

print("\nClassification Report\n")

print(
    classification_report(
        y_test,
        pred,
        target_names=[
            "Phishing",
            "Legitimate"
        ]
    )
)

# ==========================================================
# Save Model
# ==========================================================

joblib.dump(model, "random_forest_model.pkl")
joblib.dump(list(X.columns), "feature_names.pkl")

print("\nModel Saved Successfully!")

# ==========================================================
# Feature Importance
# ==========================================================

importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 20 Important Features\n")

print(importance.head(20))

importance.to_csv(
    "feature_importance.csv",
    index=False
)

print("\nFeature Importance Saved!")

print("\nTraining Completed Successfully!")