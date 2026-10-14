from urllib.parse import urlsplit
from pathlib import Path

import joblib
from flask import Flask, render_template, request

from detector import analyze_url

app = Flask(__name__)
MAX_URL_LENGTH = 2048

# Load the trained ML model once when Flask starts.
BASE_DIR = Path(__file__).resolve().parent
# Load the model evaluated using the registered-domain validation split.

# Load the validation-trained model.
# Load the validation-trained model.
BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR
    / "ML"
    / "models"
    / "phishing_validation_model.joblib"
)

PHISHING_THRESHOLD = 0.25
ml_model = joblib.load(MODEL_PATH)



@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            try:
               
                # 1. Validate the submitted URL.
                if len(url) > MAX_URL_LENGTH:
                    raise ValueError("URL exceeds the maximum length.")

                parsed_input = urlsplit(url)

                if (
                    parsed_input.scheme.lower() not in {"http", "https"}
                    or not parsed_input.hostname
                ):
                    raise ValueError(
                        "Enter a valid HTTP or HTTPS URL."
                    )

                # 2. Existing rule-based detector.
                score, findings, risk, parsed, features = analyze_url(url)


                
                # 2. ML model prediction using the validated threshold.
                probabilities = ml_model.predict_proba([url])[0]

                class_probabilities = {
                    int(label): float(probability)
                    for label, probability
                    in zip(ml_model.classes_, probabilities)
                }

                # Dataset mapping: 0 = phishing, 1 = legitimate.
                phishing_probability = class_probabilities[0]
                legitimate_probability = class_probabilities[1]

                if phishing_probability >= PHISHING_THRESHOLD:
                    ml_label = 0
                    ml_prediction = "Phishing"
                    ml_confidence = round(
                        phishing_probability * 100, 2
                    )
                else:
                    ml_label = 1
                    ml_prediction = "Legitimate"
                    ml_confidence = round(
                        legitimate_probability * 100, 2
                    )


                # 3. Compare both detection methods.
                rule_flags_phishing = risk == "HIGH"
                ml_flags_phishing = ml_prediction == "Phishing"

                if rule_flags_phishing and ml_flags_phishing:
                    combined_status = "HIGH RISK"
                    agreement = "Both detectors flag this URL as suspicious."
                    agreement_type = "agree_phishing"

                elif rule_flags_phishing or ml_flags_phishing:
                    combined_status = "REVIEW REQUIRED"
                    agreement = (
                        "The detectors disagree. Review the URL "
                        "before deciding whether to trust it."
                    )
                    agreement_type = "disagreement"

                elif risk == "MEDIUM":
                    combined_status = "REVIEW REQUIRED"
                    agreement = (
                        "The rule-based detector found warning signs, "
                        "even though both methods did not flag high risk."
                    )
                    agreement_type = "review"

                else:
                    combined_status = "LOWER DETECTED RISK"
                    agreement = (
                        "Neither detector flagged high risk. "
                        "This does not guarantee that the URL is safe."
                    )
                    agreement_type = "no_high_risk"

                result = {
                    "url": url,
                    "score": score,
                    "findings": findings,
                    "risk": risk,
                    "parsed": parsed,
                    "features": features,
                    "ml_prediction": ml_prediction,
                    "ml_label": ml_label,
                    "ml_confidence": ml_confidence,
                    "combined_status": combined_status,
                    "agreement": agreement,
                    "agreement_type": agreement_type,
                }

 
            except (ValueError, TypeError):
                result = {
                    "url": url,
                    "error": (
                        "Unable to analyze this input. "
                        "Please enter a valid HTTP or HTTPS URL."
                    ),
                }

            except Exception:
                app.logger.exception(
                    "Unexpected error while analyzing submitted URL."
                )
                result = {
                    "url": url,
                    "error": (
                        "Analysis failed unexpectedly. "
                        "Please try again."
                    ),
                }


    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=False)
