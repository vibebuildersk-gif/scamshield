import os
import joblib

from feature_extractor import extract_features


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "random_forest_model.pkl"
)

model = joblib.load(MODEL_PATH)


def predict_url(url):

    X = extract_features(url)

    prediction = model.predict(X)[0]

    probability = model.predict_proba(X)[0]

    confidence = max(probability) * 100

    result = {
        "prediction": "Legitimate" if prediction == 1 else "Phishing",
        "confidence": round(confidence, 2),
        "phishing_probability": round(probability[0] * 100, 2),
        "legitimate_probability": round(probability[1] * 100, 2),
        "features": X.to_dict(orient="records")[0]
    }

    return result


if __name__ == "__main__":

    url = input("Enter URL : ")

    result = predict_url(url)

    print("\n========== RESULT ==========\n")

    print(f"Prediction               : {result['prediction']}")
    print(f"Confidence               : {result['confidence']} %")
    print(f"Phishing Probability     : {result['phishing_probability']} %")
    print(f"Legitimate Probability   : {result['legitimate_probability']} %")