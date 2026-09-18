import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# SCAMSHIELD - IMPROVED SCAM DETECTOR
# ============================================================

DATA_PATH = "data/spam.csv"


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("Loading dataset...")

df = pd.read_csv(
    DATA_PATH,
    encoding="latin-1"
)

print(f"Dataset loaded successfully!")
print(f"Dataset shape: {df.shape}")


# ============================================================
# 2. KEEP ONLY REQUIRED COLUMNS
# ============================================================

df = df[["v1", "v2"]]

df.columns = ["label", "message"]

df = df.dropna()


# ============================================================
# 3. CONVERT LABELS
# ============================================================

df["label"] = df["label"].map({
    "ham": 0,
    "spam": 1
})


print("\nClass distribution:")
print(df["label"].value_counts())


# ============================================================
# 4. SPLIT DATA
# ============================================================

X = df["message"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining messages:", len(X_train))
print("Testing messages:", len(X_test))


# ============================================================
# 5. WORD-LEVEL TF-IDF
# ============================================================

print("\nCreating word-level TF-IDF...")

word_vectorizer = TfidfVectorizer(
    lowercase=True,
    strip_accents="unicode",
    ngram_range=(1, 2),
    min_df=1,
    max_df=0.98,
    sublinear_tf=True
)

X_train_word = word_vectorizer.fit_transform(X_train)
X_test_word = word_vectorizer.transform(X_test)


print("Word features:", X_train_word.shape[1])


# ============================================================
# 6. CHARACTER-LEVEL TF-IDF
# ============================================================

print("\nCreating character-level TF-IDF...")

char_vectorizer = TfidfVectorizer(
    analyzer="char",
    lowercase=True,
    ngram_range=(3, 5),
    min_df=2,
    sublinear_tf=True
)

X_train_char = char_vectorizer.fit_transform(X_train)
X_test_char = char_vectorizer.transform(X_test)


print("Character features:", X_train_char.shape[1])


# ============================================================
# 7. COMBINE WORD + CHARACTER FEATURES
# ============================================================

from scipy.sparse import hstack

X_train_final = hstack([
    X_train_word,
    X_train_char
])

X_test_final = hstack([
    X_test_word,
    X_test_char
])


print("\nCombined features:", X_train_final.shape[1])


# ============================================================
# 8. TRAIN NAIVE BAYES
# ============================================================

print("\nTraining ScamShield model...")

model = MultinomialNB(
    alpha=0.1
)

model.fit(
    X_train_final,
    y_train
)


# ============================================================
# 9. PREDICTIONS
# ============================================================

y_pred = model.predict(X_test_final)

probabilities = model.predict_proba(X_test_final)

spam_probability = probabilities[:, 1]


# ============================================================
# 10. EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n")
print("=" * 50)
print("SCAMSHIELD MODEL PERFORMANCE")
print("=" * 50)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Ham", "Spam"],
        digits=3
    )
)


print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    y_pred
)

print(cm)


# ============================================================
# 11. SAVE MODEL
# ============================================================

joblib.dump(
    model,
    "spam_model.pkl"
)

joblib.dump(
    word_vectorizer,
    "word_vectorizer.pkl"
)

joblib.dump(
    char_vectorizer,
    "char_vectorizer.pkl"
)

from sklearn.metrics import precision_score, recall_score, f1_score


print("\n")
print("=" * 60)
print("SCAMSHIELD THRESHOLD ANALYSIS")
print("=" * 60)

for threshold in [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]:

    threshold_predictions = (
        spam_probability >= threshold
    ).astype(int)

    precision = precision_score(
        y_test,
        threshold_predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        threshold_predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        threshold_predictions,
        zero_division=0
    )

    print(
        f"Threshold {threshold:.2f} | "
        f"Precision: {precision:.3f} | "
        f"Recall: {recall:.3f} | "
        f"F1: {f1:.3f}"
    )
print("\n")
print("=" * 50)
print("MODEL SAVED")
print("=" * 50)

print("spam_model.pkl")
print("word_vectorizer.pkl")
print("char_vectorizer.pkl")

print("\nScamShield training complete!")
