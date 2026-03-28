import pandas as pd
import numpy as np
import pickle
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from features import build_feature_matrix
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, f1_score)
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

# ─── Load dataset ──────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv('../data/raw/vulnscan_dataset.csv')
print(f"Total samples: {len(df)}")
print(f"Label distribution:\n{df['cwe_label'].value_counts()}\n")

codes = df['code'].tolist()
labels = df['cwe_label'].tolist()
is_vuln = df['is_vulnerable'].tolist()

# ─── Build features ────────────────────────────────────────────────────
print("Extracting features...")
X, tfidf_vectorizer = build_feature_matrix(codes, fit=True)
print(f"Feature matrix shape: {X.shape}")

# ─── Binary classification (vulnerable vs safe) ────────────────────────
y_binary = np.array(is_vuln)

# ─── CWE multi-class label encoding ───────────────────────────────────
label_encoder = LabelEncoder()
y_multiclass = label_encoder.fit_transform(labels)
print(f"CWE classes: {list(label_encoder.classes_)}\n")

# ─── Train/test split ─────────────────────────────────────────────────
X_train, X_test, y_train_b, y_test_b, y_train_m, y_test_m = train_test_split(
    X, y_binary, y_multiclass, test_size=0.2, random_state=42, stratify=y_binary
)
print(f"Train size: {len(X_train)}, Test size: {len(X_test)}\n")

# ─── Handle class imbalance with SMOTE ────────────────────────────────
try:
    smote = SMOTE(random_state=42, k_neighbors=min(2, len(X_train) - 1))
    X_train_bal, y_train_b_bal = smote.fit_resample(X_train, y_train_b)
    print(f"After SMOTE balancing: {len(X_train_bal)} samples")
except Exception as e:
    print(f"SMOTE skipped (small dataset): {e}")
    X_train_bal, y_train_b_bal = X_train, y_train_b

# ─── Train models and compare ─────────────────────────────────────────
print("\n" + "="*50)
print("BINARY CLASSIFICATION (Vulnerable vs Safe)")
print("="*50)

models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    "XGBoost": xgb.XGBClassifier(n_estimators=100, random_state=42,
                                   eval_metric='logloss', verbosity=0),
}

best_model = None
best_score = 0
best_name = ""

results = []
for name, model in models.items():
    model.fit(X_train_bal, y_train_b_bal)
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test_b, y_pred)
    f1 = f1_score(y_test_b, y_pred, average='weighted')
    cv_scores = cross_val_score(model, X, y_binary, cv=min(3, len(X)//5), scoring='f1_weighted')

    results.append({"Model": name, "Accuracy": f"{acc:.2%}", "F1 Score": f"{f1:.3f}",
                    "CV Mean": f"{cv_scores.mean():.3f}"})
    print(f"\n{name}:")
    print(f"  Accuracy:  {acc:.2%}")
    print(f"  F1 Score:  {f1:.3f}")
    print(f"  CV F1:     {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    if f1 > best_score:
        best_score = f1
        best_model = model
        best_name = name

print(f"\nBest model: {best_name} (F1: {best_score:.3f})")

# ─── Multi-class CWE classifier ───────────────────────────────────────
print("\n" + "="*50)
print("MULTI-CLASS CWE CLASSIFICATION")
print("="*50)

cwe_model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced')
cwe_model.fit(X_train, y_train_m)
y_pred_m = cwe_model.predict(X_test)
print(f"\nCWE Classification Report:")
print(classification_report(
    y_test_m,
    y_pred_m,
    labels=np.unique(y_test_m),
    target_names=label_encoder.inverse_transform(np.unique(y_test_m)),
    zero_division=0
))

# ─── Confusion matrix plot ─────────────────────────────────────────────
os.makedirs('../notebooks', exist_ok=True)
cm = confusion_matrix(y_test_b, best_model.predict(X_test))
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Safe', 'Vulnerable'],
            yticklabels=['Safe', 'Vulnerable'])
plt.title(f'Confusion Matrix — {best_name}')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig('../notebooks/confusion_matrix.png', dpi=150)
print("\nConfusion matrix saved to notebooks/confusion_matrix.png")
plt.close()

# ─── Feature importance plot ──────────────────────────────────────────
if hasattr(best_model, 'feature_importances_'):
    importances = best_model.feature_importances_
    feat_names = X.columns.tolist()
    top_idx = np.argsort(importances)[-15:]
    plt.figure(figsize=(8, 5))
    plt.barh([feat_names[i] for i in top_idx], importances[top_idx], color='#4f46e5')
    plt.title(f'Top 15 Features — {best_name}')
    plt.xlabel('Importance')
    plt.tight_layout()
    plt.savefig('../notebooks/feature_importance.png', dpi=150)
    print("Feature importance saved to notebooks/feature_importance.png")
    plt.close()

# ─── Save everything ──────────────────────────────────────────────────
print("\nSaving model files...")
os.makedirs('../model', exist_ok=True)

with open('../model/saved_model.pkl', 'wb') as f:
    pickle.dump(best_model, f)

with open('../model/cwe_model.pkl', 'wb') as f:
    pickle.dump(cwe_model, f)

with open('../model/tfidf_vectorizer.pkl', 'wb') as f:
    pickle.dump(tfidf_vectorizer, f)

with open('../model/label_encoder.pkl', 'wb') as f:
    pickle.dump(label_encoder, f)

# Save results table
results_df = pd.DataFrame(results)
results_df.to_csv('../notebooks/model_comparison.csv', index=False)

print("\n" + "="*50)
print("ALL FILES SAVED:")
print("  model/saved_model.pkl      <- best binary model")
print("  model/cwe_model.pkl        <- CWE type classifier")
print("  model/tfidf_vectorizer.pkl <- TF-IDF fitted vectorizer")
print("  model/label_encoder.pkl    <- CWE label encoder")
print("  notebooks/confusion_matrix.png")
print("  notebooks/feature_importance.png")
print("  notebooks/model_comparison.csv")
print("="*50)
print("\nHand these .pkl files to Person B!")