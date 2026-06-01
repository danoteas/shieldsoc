import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    roc_auc_score
)

from sklearn.ensemble import RandomForestClassifier


# -------------------------
# Load dataset
# -------------------------
df = pd.read_csv("features_v2.csv")

X = df.drop("label", axis=1)
y = df["label"]

print("Dataset shape:", df.shape)


# -------------------------
# Train / Test split
# -------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.25,
    stratify=y,
    random_state=42
)


# -------------------------
# Train model
# -------------------------
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=8,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train, y_train)


# -------------------------
# Predictions
# -------------------------
proba = model.predict_proba(X_test)[:,1]

threshold = 0.5
pred = (proba >= threshold).astype(int)

print("\n=== Classification Report ===")
print(classification_report(y_test, pred))


# -------------------------
# Confusion Matrix
# -------------------------
cm = confusion_matrix(y_test, pred)

plt.figure()
plt.title("Confusion Matrix")
plt.imshow(cm)
plt.colorbar()
plt.xlabel("Predicted")
plt.ylabel("True")
plt.show()


# -------------------------
# ROC Curve
# -------------------------
fpr, tpr, thr = roc_curve(y_test, proba)
auc = roc_auc_score(y_test, proba)

plt.figure()
plt.plot(fpr, tpr, label=f"AUC={auc:.3f}")
plt.plot([0,1],[0,1],"--")
plt.title("ROC Curve")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.legend()
plt.show()


# -------------------------
# Threshold tuning
# -------------------------
best_thr = 0
best_score = 0

for t in thr:

    p = (proba >= t).astype(int)

    tp = ((p==1) & (y_test==1)).sum()
    fp = ((p==1) & (y_test==0)).sum()

    precision = tp / (tp + fp + 1e-6)

    if precision > best_score:
        best_score = precision
        best_thr = t

print("Best precision threshold:", best_thr)


# -------------------------
# Feature importance
# -------------------------
imp = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values()

plt.figure()
imp.plot(kind="barh")
plt.title("Feature Importance")
plt.show()


# -------------------------
# Save model
# -------------------------
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")

os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "ddos_model_final.joblib")

joblib.dump(model, MODEL_PATH)

print("Model saved to:", MODEL_PATH)

