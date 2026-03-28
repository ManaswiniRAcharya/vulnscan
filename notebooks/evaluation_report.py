import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import pickle, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'model'))
from features import build_feature_matrix
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_curve, auc, precision_recall_curve)
from sklearn.model_selection import train_test_split
import numpy as np

df = pd.read_csv('../data/raw/vulnscan_dataset.csv')
with open('../model/saved_model.pkl', 'rb') as f: model = pickle.load(f)
with open('../model/tfidf_vectorizer.pkl', 'rb') as f: vec = pickle.load(f)

codes = df['code'].tolist()
y = df['is_vulnerable'].values
X, _ = build_feature_matrix(codes, tfidf_vectorizer=vec, fit=False)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

fig = plt.figure(figsize=(14, 10))
fig.suptitle('VulnScan — Model Evaluation Report', fontsize=16, fontweight='bold')
gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.4, wspace=0.3)

# Confusion matrix
ax1 = fig.add_subplot(gs[0, 0])
cm = confusion_matrix(y_test, y_pred)
ax1.imshow(cm, cmap='Blues')
ax1.set_xticks([0, 1]); ax1.set_yticks([0, 1])
ax1.set_xticklabels(['Safe', 'Vulnerable'])
ax1.set_yticklabels(['Safe', 'Vulnerable'])
ax1.set_xlabel('Predicted'); ax1.set_ylabel('Actual')
ax1.set_title('Confusion Matrix')
for i in range(2):
    for j in range(2):
        ax1.text(j, i, str(cm[i, j]), ha='center', va='center', fontsize=14,
                fontweight='bold', color='white' if cm[i,j] > cm.max()/2 else 'black')

# ROC curve
ax2 = fig.add_subplot(gs[0, 1])
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
ax2.plot(fpr, tpr, color='#4f46e5', lw=2, label=f'AUC = {roc_auc:.2f}')
ax2.plot([0,1],[0,1],'k--',lw=1)
ax2.set_xlabel('False Positive Rate'); ax2.set_ylabel('True Positive Rate')
ax2.set_title('ROC Curve'); ax2.legend()
ax2.set_xlim([0,1]); ax2.set_ylim([0,1.02])

# Precision-Recall
ax3 = fig.add_subplot(gs[1, 0])
prec, rec, _ = precision_recall_curve(y_test, y_prob)
ax3.plot(rec, prec, color='#059669', lw=2)
ax3.set_xlabel('Recall'); ax3.set_ylabel('Precision')
ax3.set_title('Precision-Recall Curve')
ax3.set_xlim([0,1]); ax3.set_ylim([0,1.02])

# Model comparison
ax4 = fig.add_subplot(gs[1, 1])
try:
    comp = pd.read_csv('../notebooks/model_comparison.csv')
    models_list = comp['Model'].tolist()
    f1_scores = [float(str(f).replace('%','')) for f in comp['F1 Score'].tolist()]
    bars = ax4.bar(models_list, f1_scores, color=['#4f46e5','#059669','#d97706'])
    ax4.set_ylabel('F1 Score'); ax4.set_title('Model Comparison')
    ax4.set_ylim([0, 1.1])
    for bar, val in zip(bars, f1_scores):
        ax4.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.02,
                f'{val:.3f}', ha='center', fontsize=10)
    ax4.set_xticklabels(models_list, rotation=10, fontsize=9)
except Exception as e:
    ax4.text(0.5, 0.5, str(e), ha='center', va='center', transform=ax4.transAxes, fontsize=8)

plt.savefig('../notebooks/evaluation_report.png', dpi=150, bbox_inches='tight')
print("Saved: notebooks/evaluation_report.png")
print("\nCLASSIFICATION REPORT:")
print(classification_report(y_test, y_pred, target_names=['Safe','Vulnerable'], zero_division=0))