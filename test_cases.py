import joblib
from scipy.sparse import hstack

MODEL_PATH = "spam_model.pkl"
WORD_VECTORIZER_PATH = "word_vectorizer.pkl"
CHAR_VECTORIZER_PATH = "char_vectorizer.pkl"

SCAM_THRESHOLD = 0.45

print("Loading ScamShield...")

model = joblib.load(MODEL_PATH)
word_vectorizer = joblib.load(WORD_VECTORIZER_PATH)
char_vectorizer = joblib.load(CHAR_VECTORIZER_PATH)

print("Model loaded successfully!\n")


def predict_message(message):

    word_features = word_vectorizer.transform([message])
    char_features = char_vectorizer.transform([message])

    features = hstack([
        word_features,
        char_features
    ])

    probabilities = model.predict_proba(features)[0]

    spam_probability = probabilities[1]

    if spam_probability >= SCAM_THRESHOLD:
        prediction = "SCAM"
    else:
        prediction = "SAFE"

    return prediction, spam_probability


test_cases = [

    # =========================
    # NORMAL / SAFE MESSAGES
    # =========================

    (
        "NORMAL",
        "Hey bro, are you coming to college tomorrow? We have a project meeting at 10.",
        "SAFE"
    ),

    (
        "NORMAL",
        "Mom, I will reach home by 8 PM today.",
        "SAFE"
    ),

    (
        "NORMAL",
        "Your order has been delivered successfully. Thank you for shopping with us.",
        "SAFE"
    ),

    (
        "NORMAL",
        "Your account has been credited with Rs 2,000. Available balance is Rs 8,450.",
        "SAFE"
    ),

    (
        "NORMAL",
        "Your electricity bill payment of Rs 1,250 was successful.",
        "SAFE"
    ),

    (
        "NORMAL",
        "Your mobile recharge of Rs 299 was successful.",
        "SAFE"
    ),

    # =========================
    # KYC SCAMS
    # =========================

    (
        "KYC SCAM",
        "URGENT: Your bank account will be blocked today. Complete your KYC immediately by clicking this link.",
        "SCAM"
    ),

    (
        "KYC SCAM",
        "Your KYC has expired. Update your PAN and Aadhaar immediately to prevent account suspension.",
        "SCAM"
    ),

    (
        "KYC SCAM",
        "Your bank account will be frozen within 24 hours. Verify your KYC now using the link below.",
        "SCAM"
    ),

    (
        "KYC SCAM",
        "Dear customer, your KYC is incomplete. Click here and submit your Aadhaar details to continue banking services.",
        "SCAM"
    ),

    # =========================
    # LOTTERY / PRIZE SCAMS
    # =========================

    (
        "LOTTERY",
        "Congratulations! You have won Rs 25,00,000 in our lucky draw. Pay Rs 5,000 processing fee to claim your prize.",
        "SCAM"
    ),

    (
        "LOTTERY",
        "Congratulations! Your mobile number has won a cash prize of Rs 10 lakh. Contact us immediately to claim your reward.",
        "SCAM"
    ),

    (
        "LOTTERY",
        "You are the lucky winner of Rs 50,00,000. Send your bank details and pay the registration fee to receive your prize.",
        "SCAM"
    ),

    # =========================
    # PARCEL SCAMS
    # =========================

    (
        "PARCEL",
        "Your parcel is on hold due to an unpaid delivery charge of Rs 25. Pay now to avoid cancellation: http://example.com",
        "SCAM"
    ),

    (
        "PARCEL",
        "Your package could not be delivered. Pay Rs 45 delivery charges immediately using this link.",
        "SCAM"
    ),

    (
        "PARCEL",
        "Your shipment is stuck at customs. Pay the clearance fee today to prevent your parcel from being returned.",
        "SCAM"
    ),

    # =========================
    # JOB SCAMS
    # =========================

    (
        "JOB SCAM",
        "Congratulations! Your profile has been selected for a work from home job. Earn Rs 50,000 per month. Send your Aadhaar and bank details to proceed.",
        "SCAM"
    ),

    (
        "JOB SCAM",
        "You have been selected for an online part time job. Earn Rs 5,000 daily. Pay Rs 999 registration fee to start.",
        "SCAM"
    ),

    (
        "JOB SCAM",
        "Work from home and earn Rs 80,000 per month. Send your bank account details and pay the security deposit immediately.",
        "SCAM"
    ),

    # =========================
    # UPI / PAYMENT SCAMS
    # =========================

    (
        "UPI SCAM",
        "Your UPI account will be blocked. Verify your account immediately by entering your UPI PIN using this link.",
        "SCAM"
    ),

    (
        "UPI SCAM",
        "You have received a payment request. Approve the UPI request and enter your PIN to receive the money.",
        "SCAM"
    ),

    (
        "UPI SCAM",
        "Your cashback is waiting. Scan this QR code and enter your UPI PIN to receive Rs 2,000.",
        "SCAM"
    ),

    # =========================
    # PHISHING
    # =========================

    (
        "PHISHING",
        "Your account has been temporarily suspended. Verify your login credentials immediately using this link.",
        "SCAM"
    ),

    (
        "PHISHING",
        "Security alert! Someone attempted to access your account. Click this link to verify your identity.",
        "SCAM"
    ),

    (
        "PHISHING",
        "Your password will expire today. Login through the link below to keep your account active.",
        "SCAM"
    ),

    # =========================
    # INVESTMENT SCAMS
    # =========================

    (
        "INVESTMENT",
        "Invest Rs 5,000 today and earn guaranteed returns of Rs 50,000 within one week. Limited slots available.",
        "SCAM"
    ),

    (
        "INVESTMENT",
        "Our AI trading platform guarantees 300% profit every month. Deposit Rs 10,000 now to activate your account.",
        "SCAM"
    ),

    # =========================
    # IMPERSONATION
    # =========================

    (
        "IMPERSONATION",
        "Hi, this is your bank manager. Your account has an issue. Send your OTP immediately so I can fix it.",
        "SCAM"
    ),

    (
        "IMPERSONATION",
        "This is the cyber crime department. Your number is involved in illegal activity. Pay Rs 10,000 immediately to avoid arrest.",
        "SCAM"
    ),
]


print("=" * 90)
print("                         SCAMSHIELD TEST SUITE")
print("=" * 90)

correct = 0
total = len(test_cases)

results = []

for category, message, expected in test_cases:

    prediction, probability = predict_message(message)

    if prediction == expected:
        status = "PASS"
        correct += 1
    else:
        status = "FAIL"

    results.append(
        (category, expected, prediction, probability, status)
    )


print(
    f"\n{'CATEGORY':<15}"
    f"{'EXPECTED':<12}"
    f"{'PREDICTED':<12}"
    f"{'SCAM %':<10}"
    f"{'STATUS'}"
)

print("-" * 90)

for category, expected, prediction, probability, status in results:

    print(
        f"{category:<15}"
        f"{expected:<12}"
        f"{prediction:<12}"
        f"{probability * 100:>7.2f}%   "
        f"{status}"
    )


accuracy = (correct / total) * 100

print("\n" + "=" * 90)

print(f"Tests Passed : {correct}/{total}")
print(f"Tests Failed : {total - correct}/{total}")
print(f"Functional Test Accuracy : {accuracy:.2f}%")

print("=" * 90)

print("\nFailed Cases:")

failed_found = False

for category, expected, prediction, probability, status in results:

    if status == "FAIL":

        failed_found = True

        print("\n" + "-" * 70)
        print(f"Category : {category}")
        print(f"Expected : {expected}")
        print(f"Predicted: {prediction}")
        print(f"Spam Probability: {probability * 100:.2f}%")

if not failed_found:
    print("No failed cases!")

print("\nScamShield testing completed.")