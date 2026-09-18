import joblib

model = joblib.load("spam_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")

print("🛡️ ScamShield Model Tester")
print("===========================")

while True:
    message = input("\nEnter a message (or type 'exit'): ")

    if message.lower() == "exit":
        break

    message_vector = vectorizer.transform([message])

    prediction = model.predict(message_vector)[0]

    probabilities = model.predict_proba(message_vector)[0]

    if prediction == 1:
        print("\n🚨 SCAM / SPAM")
        print(f"Confidence: {probabilities[1] * 100:.2f}%")
    else:
        print("\n✅ SAFE / HAM")
        print(f"Confidence: {probabilities[0] * 100:.2f}%")