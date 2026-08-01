import os
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier

print("=" * 70)
print("PHIUSIIL DATASET LEAKAGE CHECK")
print("=" * 70)

# ==========================================================
# Dataset Path
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.abspath(
    os.path.join(
        BASE_DIR,
        "..",
        "..",
        "dataset",
        "PhiUSIIL_Phishing_URL_Dataset.csv"
    )
)

print("\nDataset Path:")
print(DATASET_PATH)

if not os.path.exists(DATASET_PATH):
    print("\n❌ Dataset not found!")
    exit()

# ==========================================================
# Load Dataset
# ==========================================================

df = pd.read_csv(DATASET_PATH)

print("\nOriginal Dataset Shape :", df.shape)

# ==========================================================
# Remove Duplicate URLs
# ==========================================================

df = df.drop_duplicates(subset=["URL"])

print("After Removing Duplicates :", df.shape)

# ==========================================================
# Remove Text Columns
# ==========================================================

DROP_COLUMNS = [
    "FILENAME",
    "URL",
    "Domain",
    "Title",
    "TLD"
]

df = df.drop(columns=DROP_COLUMNS)

print("\nTraining Dataset Shape :", df.shape)

# ==========================================================
# Features & Labels
# ==========================================================

X = df.drop(columns=["label"])
y = df["label"]

print("Number of Features :", len(X.columns))

# ==========================================================
# Train Random Forest
# ==========================================================

print("\nTraining Random Forest...\n")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1
)

model.fit(X, y)

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

print("=" * 70)
print("TOP 30 IMPORTANT FEATURES")
print("=" * 70)

print(importance.head(30).to_string(index=False))

# ==========================================================
# Save Feature Importance CSV
# ==========================================================

CSV_PATH = os.path.join(
    BASE_DIR,
    "feature_importance.csv"
)

importance.to_csv(
    CSV_PATH,
    index=False
)

# ==========================================================
# Correlation
# ==========================================================

correlation = df.corr(numeric_only=True)["label"]

correlation = correlation.abs()

correlation = correlation.sort_values(
    ascending=False
)

CORR_PATH = os.path.join(
    BASE_DIR,
    "feature_correlation.csv"
)

correlation.to_csv(CORR_PATH)

print("\n")
print("=" * 70)
print("TOP 20 CORRELATED FEATURES")
print("=" * 70)

print(correlation.head(20).to_string())

# ==========================================================
# Plot
# ==========================================================

top20 = importance.head(20)

plt.figure(figsize=(12, 8))

plt.barh(
    top20["Feature"],
    top20["Importance"]
)

plt.gca().invert_yaxis()

plt.xlabel("Importance")

plt.title("Top 20 Feature Importance")

plt.tight_layout()

PLOT_PATH = os.path.join(
    BASE_DIR,
    "feature_importance.png"
)

plt.savefig(
    PLOT_PATH,
    dpi=300
)

plt.close()

# ==========================================================
# Leakage Warning
# ==========================================================

print("\n")
print("=" * 70)
print("POTENTIAL DATA LEAKAGE FEATURES")
print("=" * 70)

suspected = [
    "URLSimilarityIndex",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "NoOfExternalRef",
    "LineOfCode",
    "LargestLineLength",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS"
]

for feature in suspected:

    if feature in importance["Feature"].values:

        score = importance.loc[
            importance["Feature"] == feature,
            "Importance"
        ].values[0]

        print(f"{feature:30} {score:.6f}")

print("\n")
print("=" * 70)
print("FILES GENERATED")
print("=" * 70)

print("✓ feature_importance.csv")
print("✓ feature_importance.png")
print("✓ feature_correlation.csv")

print("\nDone.")