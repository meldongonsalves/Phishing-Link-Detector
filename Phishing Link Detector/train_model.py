"""
train_model.py
==============
Trains a Logistic Regression classifier for phishing URL detection.
Outputs trained weights directly into model.js for the Chrome extension.

Dataset: phishing_dataset.csv (generated from UCI phishing research statistics)
         Features match exactly what featureExtractor.js extracts from URLs.

Usage:
    python train_model.py

Output:
    - model.js         (updated with trained weights)
    - evaluation.txt   (accuracy, precision, recall, F1, confusion matrix)
    - training_results.png (ROC curve + feature importance chart)

Author: Meldon
Project: AI-Powered Phishing Link Detector - Chrome Extension
"""

import pandas as pd
import numpy as np
import json
import os
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score, roc_curve
)
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving plots
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

# ─── CONFIG ───────────────────────────────────────────────────────────────────
DATASET_PATH  = 'phishing_dataset.csv'
MODEL_JS_PATH = 'model.js'
EVAL_PATH     = 'evaluation.txt'
PLOT_PATH     = 'training_results.png'
TEST_SIZE     = 0.2   # 80% train, 20% test
RANDOM_STATE  = 42

FEATURES = [
    'urlLength',
    'numDots',
    'numHyphens',
    'hasHttps',
    'hasIpAddress',
    'suspiciousKeywordCount',
    'hasAtSymbol',
    'numSubdomains',
    'hasEncoding',
    'domainLength',
    'hasDigitsInDomain',
    'brandInSubdomain',
    'isTyposquat',
    'hasSuspiciousTld',
    'scamKeywordCount',
    'isLongCompoundDomain',
]

# ─── LOAD DATA ────────────────────────────────────────────────────────────────
print("=" * 60)
print("  Phishing URL Detector — Model Training")
print("=" * 60)

df = pd.read_csv(DATASET_PATH)
print(f"\n[1] Dataset loaded: {len(df):,} URLs")
print(f"    Phishing:    {df['label'].sum():,} ({df['label'].mean()*100:.1f}%)")
print(f"    Legitimate:  {(df['label']==0).sum():,} ({(1-df['label'].mean())*100:.1f}%)")
print(f"    Features:    {len(FEATURES)}")

X = df[FEATURES].values
y = df['label'].values

# ─── TRAIN / TEST SPLIT ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
)
print(f"\n[2] Train/test split: {len(X_train)} train / {len(X_test)} test")

# ─── SCALE FEATURES ──────────────────────────────────────────────────────────
# StandardScaler normalises features so large-range ones (urlLength)
# don't dominate small-range ones (hasHttps)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# ─── TRAIN MODEL ─────────────────────────────────────────────────────────────
print("\n[3] Training Logistic Regression model...")
model = LogisticRegression(
    max_iter=1000,
    random_state=RANDOM_STATE,
    solver='lbfgs',
    C=1.0  # Regularisation strength
)
model.fit(X_train_scaled, y_train)

# Cross-validation score
cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='accuracy')
print(f"    5-fold CV accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

# ─── EVALUATE ─────────────────────────────────────────────────────────────────
print("\n[4] Evaluating on test set...")
y_pred      = model.predict(X_test_scaled)
y_pred_prob = model.predict_proba(X_test_scaled)[:, 1]

accuracy  = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall    = recall_score(y_test, y_pred)
f1        = f1_score(y_test, y_pred)
auc       = roc_auc_score(y_test, y_pred_prob)
cm        = confusion_matrix(y_test, y_pred)

tn, fp, fn, tp = cm.ravel()
false_positive_rate = fp / (fp + tn)

print(f"\n    ┌─────────────────────────────────┐")
print(f"    │  Accuracy:           {accuracy*100:6.2f}%    │")
print(f"    │  Precision:          {precision*100:6.2f}%    │")
print(f"    │  Recall:             {recall*100:6.2f}%    │")
print(f"    │  F1 Score:           {f1*100:6.2f}%    │")
print(f"    │  AUC-ROC:            {auc*100:6.2f}%    │")
print(f"    │  False Positive Rate:{false_positive_rate*100:6.2f}%    │")
print(f"    └─────────────────────────────────┘")
print(f"\n    Confusion Matrix:")
print(f"    True Negatives  (correct safe):    {tn:4d}")
print(f"    True Positives  (correct phishing):{tp:4d}")
print(f"    False Positives (wrongly flagged):  {fp:4d}")
print(f"    False Negatives (missed phishing):  {fn:4d}")

# ─── EXTRACT WEIGHTS FOR model.js ────────────────────────────────────────────
# The scaler transforms features: x_scaled = (x - mean) / std
# The logistic regression decision: z = bias + sum(w_i * x_scaled_i)
# To get unscaled weights compatible with raw feature values:
# w_unscaled_i = w_scaled_i / std_i
# bias_unscaled = bias_scaled - sum(w_scaled_i * mean_i / std_i)

coef    = model.coef_[0]
intercept = model.intercept_[0]
means   = scaler.mean_
stds    = scaler.scale_

# Convert to unscaled weights (so model.js works with raw feature values)
unscaled_weights = coef / stds
unscaled_bias    = intercept - np.sum(coef * means / stds)

print(f"\n[5] Trained weights (unscaled, for model.js):")
print(f"    {'Feature':<28} {'Weight':>10}")
print(f"    {'-'*40}")
print(f"    {'bias':<28} {unscaled_bias:>10.4f}")
for feat, w in sorted(zip(FEATURES, unscaled_weights), key=lambda x: abs(x[1]), reverse=True):
    bar = '█' * int(abs(w) * 3)
    direction = '+' if w > 0 else '-'
    print(f"    {feat:<28} {w:>10.4f}  {direction}{bar}")

# ─── WRITE model.js ──────────────────────────────────────────────────────────
print(f"\n[6] Writing trained weights to {MODEL_JS_PATH}...")

def fmt(v):
    return f"{v:.4f}"

model_js_content = f"""// model.js
// Logistic Regression classifier for phishing URL detection.
// Weights trained by train_model.py on phishing URL dataset.
//
// Training results:
//   Accuracy:           {accuracy*100:.2f}%
//   Precision:          {precision*100:.2f}%
//   Recall:             {recall*100:.2f}%
//   F1 Score:           {f1*100:.2f}%
//   AUC-ROC:            {auc*100:.2f}%
//   False Positive Rate:{false_positive_rate*100:.2f}%
//   Training set:       {len(X_train)} URLs
//   Test set:           {len(X_test)} URLs
//   Cross-val accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)

const MODEL_WEIGHTS = {{
  bias:                   {fmt(unscaled_bias)},   // trained intercept

  // URL structure features
  urlLength:              {fmt(unscaled_weights[FEATURES.index('urlLength')])},
  numDots:                {fmt(unscaled_weights[FEATURES.index('numDots')])},
  numHyphens:             {fmt(unscaled_weights[FEATURES.index('numHyphens')])},
  hasHttps:               {fmt(unscaled_weights[FEATURES.index('hasHttps')])},
  domainLength:           {fmt(unscaled_weights[FEATURES.index('domainLength')])},

  // Strong phishing signals
  hasIpAddress:           {fmt(unscaled_weights[FEATURES.index('hasIpAddress')])},
  hasAtSymbol:            {fmt(unscaled_weights[FEATURES.index('hasAtSymbol')])},
  brandInSubdomain:       {fmt(unscaled_weights[FEATURES.index('brandInSubdomain')])},
  isTyposquat:            {fmt(unscaled_weights[FEATURES.index('isTyposquat')])},

  // Keyword and pattern signals
  suspiciousKeywordCount: {fmt(unscaled_weights[FEATURES.index('suspiciousKeywordCount')])},
  numSubdomains:          {fmt(unscaled_weights[FEATURES.index('numSubdomains')])},
  hasEncoding:            {fmt(unscaled_weights[FEATURES.index('hasEncoding')])},
  hasDigitsInDomain:      {fmt(unscaled_weights[FEATURES.index('hasDigitsInDomain')])},
  hasSuspiciousTld:       {fmt(unscaled_weights[FEATURES.index('hasSuspiciousTld')])},
  scamKeywordCount:       {fmt(unscaled_weights[FEATURES.index('scamKeywordCount')])},
  isLongCompoundDomain:   {fmt(unscaled_weights[FEATURES.index('isLongCompoundDomain')])},
}};

function sigmoid(z) {{
  return 1 / (1 + Math.exp(-z));
}}

function computePhishingProbability(features) {{
  if (!features) return 0;

  let z = MODEL_WEIGHTS.bias;
  z += (features.urlLength              || 0) * MODEL_WEIGHTS.urlLength;
  z += (features.numDots                || 0) * MODEL_WEIGHTS.numDots;
  z += (features.numHyphens             || 0) * MODEL_WEIGHTS.numHyphens;
  z += (features.hasHttps               || 0) * MODEL_WEIGHTS.hasHttps;
  z += (features.hasIpAddress           || 0) * MODEL_WEIGHTS.hasIpAddress;
  z += (features.suspiciousKeywordCount || 0) * MODEL_WEIGHTS.suspiciousKeywordCount;
  z += (features.hasAtSymbol            || 0) * MODEL_WEIGHTS.hasAtSymbol;
  z += (features.numSubdomains          || 0) * MODEL_WEIGHTS.numSubdomains;
  z += (features.hasEncoding            || 0) * MODEL_WEIGHTS.hasEncoding;
  z += (features.domainLength           || 0) * MODEL_WEIGHTS.domainLength;
  z += (features.hasDigitsInDomain      || 0) * MODEL_WEIGHTS.hasDigitsInDomain;
  z += (features.brandInSubdomain       || 0) * MODEL_WEIGHTS.brandInSubdomain;
  z += (features.isTyposquat            || 0) * MODEL_WEIGHTS.isTyposquat;
  z += (features.hasSuspiciousTld       || 0) * MODEL_WEIGHTS.hasSuspiciousTld;
  z += (features.scamKeywordCount       || 0) * MODEL_WEIGHTS.scamKeywordCount;
  z += (features.isLongCompoundDomain   || 0) * MODEL_WEIGHTS.isLongCompoundDomain;

  return sigmoid(z);
}}
"""

with open(MODEL_JS_PATH, 'w') as f:
    f.write(model_js_content)
print(f"    model.js written with trained weights")

# ─── SAVE EVALUATION REPORT ──────────────────────────────────────────────────
eval_text = f"""PHISHING URL DETECTOR — MODEL EVALUATION REPORT
================================================
Project:    AI-Powered Phishing Link Detector Chrome Extension
Algorithm:  Logistic Regression (scikit-learn)
Dataset:    {len(df):,} URLs ({df['label'].sum():,} phishing, {(df['label']==0).sum():,} legitimate)
Train/Test: {len(X_train)}/{len(X_test)} (80/20 split, stratified)

PERFORMANCE METRICS
-------------------
Accuracy:             {accuracy*100:.2f}%
Precision:            {precision*100:.2f}%
Recall (Sensitivity): {recall*100:.2f}%
F1 Score:             {f1*100:.2f}%
AUC-ROC:              {auc*100:.2f}%
False Positive Rate:  {false_positive_rate*100:.2f}%

5-Fold Cross-Validation:
  Mean Accuracy: {cv_scores.mean()*100:.2f}%
  Std Dev:       {cv_scores.std()*100:.2f}%
  All folds:     {', '.join([f'{s*100:.1f}%' for s in cv_scores])}

CONFUSION MATRIX
----------------
                    Predicted Safe  Predicted Phishing
Actual Safe         {tn:8d}        {fp:8d}
Actual Phishing     {fn:8d}        {tp:8d}

True Negatives  (correctly identified safe):     {tn}
True Positives  (correctly identified phishing): {tp}
False Positives (legitimate sites wrongly flagged): {fp}
False Negatives (phishing sites missed):         {fn}

CLASSIFICATION REPORT
---------------------
{classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])}

FEATURE WEIGHTS (sorted by importance)
---------------------------------------
{'Feature':<28} {'Weight':>10}  {'Direction'}
{'-'*55}
{'bias (intercept)':<28} {unscaled_bias:>10.4f}
"""
for feat, w in sorted(zip(FEATURES, unscaled_weights), key=lambda x: abs(x[1]), reverse=True):
    direction = 'phishing indicator' if w > 0 else 'safe indicator'
    eval_text += f"{feat:<28} {w:>10.4f}  {direction}\n"

with open(EVAL_PATH, 'w') as f:
    f.write(eval_text)
print(f"    evaluation.txt written")

# ─── PLOT ROC CURVE + FEATURE IMPORTANCE ─────────────────────────────────────
print(f"\n[7] Generating charts...")
fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle('Phishing URL Detector — Model Training Results', fontsize=14, fontweight='bold')

# ROC Curve
fpr_vals, tpr_vals, _ = roc_curve(y_test, y_pred_prob)
axes[0].plot(fpr_vals, tpr_vals, color='#ff3c5a', lw=2, label=f'ROC Curve (AUC = {auc:.3f})')
axes[0].plot([0, 1], [0, 1], color='gray', linestyle='--', lw=1, label='Random Classifier')
axes[0].fill_between(fpr_vals, tpr_vals, alpha=0.1, color='#ff3c5a')
axes[0].set_xlabel('False Positive Rate', fontsize=11)
axes[0].set_ylabel('True Positive Rate', fontsize=11)
axes[0].set_title('ROC Curve', fontsize=12)
axes[0].legend(loc='lower right')
axes[0].grid(True, alpha=0.3)
axes[0].set_facecolor('#f8f9fa')

# Annotate key metrics on ROC
axes[0].annotate(
    f'Accuracy: {accuracy*100:.1f}%\nF1: {f1*100:.1f}%\nFPR: {false_positive_rate*100:.1f}%',
    xy=(0.55, 0.15), fontsize=9,
    bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='gray')
)

# Feature importance
feat_weights = list(zip(FEATURES, unscaled_weights))
feat_weights.sort(key=lambda x: x[1])
feats, weights = zip(*feat_weights)
colors = ['#ff3c5a' if w > 0 else '#00e5a0' for w in weights]
bars = axes[1].barh(feats, weights, color=colors, edgecolor='white', linewidth=0.5)
axes[1].axvline(x=0, color='black', linewidth=0.8)
axes[1].set_xlabel('Weight (positive = phishing signal)', fontsize=11)
axes[1].set_title('Feature Weights (Logistic Regression)', fontsize=12)
axes[1].grid(True, alpha=0.3, axis='x')
axes[1].set_facecolor('#f8f9fa')

# Add legend
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='#ff3c5a', label='Phishing indicator (+)'),
    Patch(facecolor='#00e5a0', label='Safe indicator (-)')
]
axes[1].legend(handles=legend_elements, loc='lower right', fontsize=9)

plt.tight_layout()
plt.savefig(PLOT_PATH, dpi=150, bbox_inches='tight', facecolor='white')
print(f"    training_results.png saved")

print(f"\n{'='*60}")
print(f"  Training complete!")
print(f"{'='*60}")
print(f"\n  Files generated:")
print(f"  ├── model.js           — update your extension with this")
print(f"  ├── evaluation.txt     — include metrics in your report")
print(f"  └── training_results.png — include charts in your report")
print(f"\n  Key results for your report:")
print(f"  • Accuracy:  {accuracy*100:.2f}%")
print(f"  • F1 Score:  {f1*100:.2f}%")
print(f"  • AUC-ROC:   {auc*100:.2f}%")
print(f"  • FPR:       {false_positive_rate*100:.2f}% (false alarms)")
