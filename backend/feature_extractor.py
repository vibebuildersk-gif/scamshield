import os
import joblib
import pandas as pd

from utils.url_features import extract_url_features
from utils.html_features import extract_html_features


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FEATURE_FILE = os.path.join(
    BASE_DIR,
    "models",
    "feature_names.pkl"
)


def extract_features(url):
    """
    Returns a DataFrame with columns in the
    exact order used while training.
    """

    feature_names = joblib.load(FEATURE_FILE)

    url_features = extract_url_features(url)
    html_features = extract_html_features(url)

    features = {}

    features.update(url_features)
    features.update(html_features)

    final = {}

    for feature in feature_names:

        final[feature] = features.get(feature, 0)

    return pd.DataFrame([final])


if __name__ == "__main__":

    url = input("Enter URL : ")

    df = extract_features(url)

    print("\n========== FEATURE VECTOR ==========\n")

    print(df.T)

    print("\nShape :", df.shape)