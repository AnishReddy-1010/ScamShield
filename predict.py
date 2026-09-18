import joblib
from scipy.sparse import hstack

from risk_engine import analyze_message


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "spam_model.pkl"
WORD_VECTORIZER_PATH = "word_vectorizer.pkl"
CHAR_VECTORIZER_PATH = "char_vectorizer.pkl"

# Threshold selected during model evaluation
SCAM_THRESHOLD = 0.45


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading ScamShield AI model...")

model = joblib.load(MODEL_PATH)
word_vectorizer = joblib.load(WORD_VECTORIZER_PATH)
char_vectorizer = joblib.load(CHAR_VECTORIZER_PATH)

print("ScamShield AI model loaded successfully!")


# ============================================================
# ML PREDICTION
# ============================================================

def predict_message(message):
    """
    Run the trained ML classifier on a single message.

    Returns:
        ml_prediction
        spam_probability
        safe_probability
    """

    if not isinstance(message, str):
        message = str(message)

    message = message.strip()

    if not message:
        raise ValueError("Message cannot be empty.")

    # Word-level TF-IDF features
    word_features = word_vectorizer.transform([message])

    # Character-level TF-IDF features
    char_features = char_vectorizer.transform([message])

    # Combine both feature sets
    features = hstack([
        word_features,
        char_features
    ])

    # Model probabilities
    probabilities = model.predict_proba(features)[0]

    safe_probability = float(probabilities[0])
    spam_probability = float(probabilities[1])

    # ML classification
    if spam_probability >= SCAM_THRESHOLD:
        ml_prediction = "SCAM"
    else:
        ml_prediction = "SAFE"

    return {
        "ml_prediction": ml_prediction,
        "spam_probability": spam_probability,
        "safe_probability": safe_probability
    }


# ============================================================
# COMPLETE SCAMSHIELD ANALYSIS
# ============================================================

def analyze_message_complete(message):
    """
    Complete ScamShield pipeline.

    ML Model
        ↓
    Spam Probability
        ↓
    Risk Engine
        ↓
    Final Risk Assessment
    """

    if not isinstance(message, str):
        message = str(message)

    message = message.strip()

    if not message:
        raise ValueError("Message cannot be empty.")

    # --------------------------------------------------------
    # STEP 1 — ML ANALYSIS
    # --------------------------------------------------------

    ml_result = predict_message(message)

    # --------------------------------------------------------
    # STEP 2 — RISK ENGINE
    # --------------------------------------------------------

    risk_result = analyze_message(
        message,
        ml_result["spam_probability"]
    )

    # --------------------------------------------------------
    # STEP 3 — COMBINE RESULTS
    # --------------------------------------------------------

    result = {
        **ml_result,
        **risk_result
    }

    return result


# ============================================================
# TERMINAL TEST INTERFACE
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 65)
    print("                    🛡️ SCAMSHIELD")
    print("              AI Scam Detection Engine")
    print("=" * 65)

    while True:

        message = input(
            "\nPaste a message (or type 'exit'): "
        )

        if message.lower().strip() == "exit":

            print("\nScamShield closed.")
            break

        if not message.strip():

            print("Please enter a message.")
            continue

        try:

            result = analyze_message_complete(message)

            print()
            print("-" * 65)

            # =================================================
            # RISK RESULT
            # =================================================

            if result["risk_level"] == "HIGH RISK":

                print("🚨 RESULT: HIGH RISK")

            elif result["risk_level"] == "SUSPICIOUS":

                print("⚠️ RESULT: SUSPICIOUS")

            else:

                print("✅ RESULT: LOW RISK")

            print(
                f"\nRisk Score: "
                f"{result['risk_score']:.2f}/100"
            )

            print(
                f"Scam Type: "
                f"{result['scam_type']}"
            )

            # =================================================
            # ML INFORMATION
            # =================================================

            print("\n🤖 ML ANALYSIS")

            print(
                f"Spam Probability: "
                f"{result['spam_probability'] * 100:.2f}%"
            )

            print(
                f"Safe Probability: "
                f"{result['safe_probability'] * 100:.2f}%"
            )

            print(
                f"ML Prediction: "
                f"{result['ml_prediction']}"
            )

            # =================================================
            # INDICATORS
            # =================================================

            print("\n🔍 DETECTED INDICATORS")

            if result["indicators"]:

                for indicator in result["indicators"]:

                    print(f"  • {indicator}")

            else:

                print(
                    "  • No strong scam indicators detected"
                )

            # =================================================
            # RECOMMENDATION
            # =================================================

            print("\n🛡️ SAFETY RECOMMENDATION")

            print(
                f"  {result['recommendation']}"
            )

            print("\n" + "-" * 65)

        except Exception as error:

            print(
                f"\n❌ ScamShield Error: {error}"
            )