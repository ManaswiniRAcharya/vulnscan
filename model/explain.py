#!/usr/bin/env python3
"""
VulnScan SHAP Explainability Module
Part 6: Explain AI predictions using SHAP values
"""

import pickle
import numpy as np
import shap
import matplotlib.pyplot as plt
import sys
import os

# ─── SETUP PATHS ─────────────────────────────────────────────────────
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, 'model')
NOTEBOOKS_DIR = os.path.join(PROJECT_ROOT, 'notebooks')

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

# ─── IMPORT FEATURES MODULE ────────────────────────────────────────────
try:
    from features import build_feature_matrix
    print("✅ Features module imported successfully")
except ImportError as e:
    print(f"❌ Error importing features module: {e}")
    sys.exit(1)

# ─── LOAD MODELS ──────────────────────────────────────────────────────
print("Loading models from:", MODEL_DIR)
model = None
tfidf_vectorizer = None

def load_models():
    """Load the trained ML models and vectorizer."""
    global model, tfidf_vectorizer
    
    required_files = ['saved_model.pkl', 'tfidf_vectorizer.pkl']
    
    for filename in required_files:
        filepath = os.path.join(MODEL_DIR, filename)
        if not os.path.exists(filepath):
            print(f"❌ Missing file: {filename}")
            print("   Run train.py first to generate model files!")
            return False
    
    try:
        with open(os.path.join(MODEL_DIR, 'saved_model.pkl'), 'rb') as f:
            model = pickle.load(f)
        with open(os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl'), 'rb') as f:
            tfidf_vectorizer = pickle.load(f)
        print("✅ All models loaded successfully!")
        return True
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        return False

# ─── EXPLANATION FUNCTION ─────────────────────────────────────────────
def explain_prediction(code_string, top_n=5):
    """
    Explain why a code snippet was classified as vulnerable or safe.
    """
    if model is None or tfidf_vectorizer is None:
        if not load_models():
            return None
    
    try:
        # Build feature matrix
        X, _ = build_feature_matrix([code_string], tfidf_vectorizer=tfidf_vectorizer, fit=False)
        feature_names = X.columns.tolist()
        n_features = len(feature_names)
        
        # Get prediction
        prediction = int(model.predict(X)[0])  # 0 = SAFE, 1 = VULNERABLE
        probability = model.predict_proba(X)[0]
        confidence = float(max(probability))
        
        # SHAP explanation
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        
        # ─── CRITICAL FIX: Handle SHAP output correctly ───────────────
        # For binary classification, shap_values can be:
        # 1. List of 2 arrays [class_0_shap, class_1_shap] - CORRECT format
        # 2. Single flat array with 2*n_features (concatenated classes) - WRONG format
        # 3. Single array with n_features - Old sklearn format
        
        sv = None
        
        if isinstance(shap_values, list):
            # ✅ CORRECT: List format - select predicted class
            if len(shap_values) > prediction:
                sv = np.array(shap_values[prediction][0]).flatten()
            else:
                sv = np.array(shap_values[0][0]).flatten()
        else:
            # Single array - check if it's concatenated (2*n_features)
            flat_shap = np.array(shap_values).flatten()
            
            if len(flat_shap) == 2 * n_features:
                # ⚠️ Concatenated format: [class_0_features, class_1_features]
                # Extract only the predicted class portion
                if prediction == 0:
                    sv = flat_shap[:n_features]  # First half = SAFE class
                else:
                    sv = flat_shap[n_features:]  # Second half = VULNERABLE class
            elif len(flat_shap) == n_features:
                # ✅ Correct single array
                sv = flat_shap
            else:
                # Unknown format - truncate to match
                print(f"⚠️  Unexpected SHAP shape: {len(flat_shap)}, using first {n_features}")
                sv = flat_shap[:n_features]
        
        # Final safety check
        if len(sv) != n_features:
            print(f"⚠️  Shape mismatch: SHAP ({len(sv)}) vs features ({n_features}), truncating")
            sv = sv[:n_features]
        
        # Get top features
        abs_values = np.abs(sv)
        sorted_indices = np.argsort(abs_values)[::-1]
        
        explanations = []
        count = 0
        for idx in sorted_indices:
            if count >= top_n:
                break
            if idx >= n_features:
                continue
                
            feat = feature_names[idx]
            value = float(X.iloc[0, idx])
            impact = float(sv[idx])
            
            if abs(impact) > 0.0001:
                direction = "increases risk" if impact > 0 else "decreases risk"
                # For safe predictions, invert the interpretation
                if prediction == 0 and impact > 0:
                    direction = "pushed toward vulnerable (but overall safe)"
                elif prediction == 0 and impact < 0:
                    direction = "confirms safety"
                
                explanations.append({
                    "feature": feat,
                    "value": round(value, 4),
                    "impact": round(impact, 6),
                    "direction": direction,
                    "abs_impact": round(abs(impact), 6)
                })
                count += 1
        
        return {
            "is_vulnerable": bool(prediction),
            "confidence": round(confidence, 4),
            "top_features": explanations,
            "total_features": n_features,
            "prediction_class": prediction
        }
        
    except Exception as e:
        print(f"❌ Error in explain_prediction: {e}")
        import traceback
        traceback.print_exc()
        return None

# ─── SHAP PLOT FUNCTION ───────────────────────────────────────────────
def generate_shap_plot(codes, labels=None, save_path=None):
    """Generate a SHAP summary plot for multiple code samples."""
    if model is None or tfidf_vectorizer is None:
        if not load_models():
            return False
    
    if save_path is None:
        os.makedirs(NOTEBOOKS_DIR, exist_ok=True)
        save_path = os.path.join(NOTEBOOKS_DIR, 'shap_summary.png')
    
    try:
        print(f"Building features for {len(codes)} code samples...")
        X, _ = build_feature_matrix(codes, tfidf_vectorizer=tfidf_vectorizer, fit=False)
        
        print("Calculating SHAP values...")
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        
        plt.figure(figsize=(12, 8))
        
        # Handle different SHAP formats for plotting
        if isinstance(shap_values, list) and len(shap_values) >= 2:
            # Use class 1 (vulnerable) for summary plot
            plot_values = shap_values[1]
            if len(plot_values.shape) == 1:
                plot_values = plot_values.reshape(1, -1)
        else:
            # Single array - check shape
            plot_values = np.array(shap_values)
            if len(plot_values.shape) == 1:
                plot_values = plot_values.reshape(1, -1)
            # If concatenated, take second half (vulnerable class)
            if plot_values.shape[1] == 2 * X.shape[1]:
                n_feat = X.shape[1]
                plot_values = plot_values[:, n_feat:]  # Take vulnerable class
        
        shap.summary_plot(plot_values, X, show=False, max_display=15)
        plt.title("SHAP Feature Importance (Vulnerable Class)", fontsize=14, pad=20)
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"✅ SHAP summary plot saved to: {save_path}")
        return True
        
    except Exception as e:
        print(f"❌ Error generating SHAP plot: {e}")
        import traceback
        traceback.print_exc()
        return False

# ─── BATCH EXPLANATION ───────────────────────────────────────────────
def explain_batch(codes_with_names):
    """Explain predictions for multiple code samples."""
    results = []
    for name, code in codes_with_names:
        print(f"\nAnalyzing: {name}")
        explanation = explain_prediction(code)
        if explanation:
            explanation['name'] = name
            results.append(explanation)
    return results

# ─── MAIN TEST ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 70)
    print("VULNSCAN SHAP EXPLAINABILITY - PART 6")
    print("=" * 70)
    
    if not load_models():
        print("\n❌ Failed to load models. Exiting.")
        sys.exit(1)
    
    # Test 1: SQL Injection
    print("\n" + "-" * 70)
    print("TEST 1: SQL Injection (CWE-89)")
    print("-" * 70)
    
    sql_injection_code = """def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)"""
    
    print("Code:")
    print(sql_injection_code)
    
    result = explain_prediction(sql_injection_code)
    if result:
        status = "🔴 VULNERABLE" if result['is_vulnerable'] else "🟢 SAFE"
        print(f"\n{status} (confidence: {result['confidence']:.1%})")
        print(f"\n📊 Key Factors:")
        for i, feat in enumerate(result['top_features'][:5], 1):
            emoji = "🔴" if "increases" in feat['direction'] else "🟢"
            print(f"   {i}. {emoji} {feat['feature']}")
            print(f"      Value: {feat['value']:.2f} | Impact: {feat['abs_impact']:.4f}")
            print(f"      → {feat['direction']}")
    
    # Test 2: Safe Code
    print("\n" + "-" * 70)
    print("TEST 2: Safe SQL (Parameterized Query)")
    print("-" * 70)
    
    safe_code = """def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (username,))"""
    
    print("Code:")
    print(safe_code)
    
    result = explain_prediction(safe_code)
    if result:
        status = "🔴 VULNERABLE" if result['is_vulnerable'] else "🟢 SAFE"
        print(f"\n{status} (confidence: {result['confidence']:.1%})")
        print(f"\n📊 Key Factors:")
        for i, feat in enumerate(result['top_features'][:3], 1):
            emoji = "🔴" if "increases" in feat['direction'] else "🟢"
            print(f"   {i}. {emoji} {feat['feature']}")
            print(f"      Value: {feat['value']:.2f} | Impact: {feat['abs_impact']:.4f}")
            print(f"      → {feat['direction']}")
    
    # Test 3: OS Command Injection
    print("\n" + "-" * 70)
    print("TEST 3: OS Command Injection (CWE-78)")
    print("-" * 70)
    
    cmd_code = """def ping_host(host):
    os.system("ping " + host)"""
    
    print("Code:")
    print(cmd_code)
    
    result = explain_prediction(cmd_code)
    if result:
        status = "🔴 VULNERABLE" if result['is_vulnerable'] else "🟢 SAFE"
        print(f"\n{status} (confidence: {result['confidence']:.1%})")
        if result['top_features']:
            top = result['top_features'][0]
            print(f"   Main factor: {top['feature']} = {top['value']:.2f}")
    
    # Test 4: Generate SHAP Summary Plot
    print("\n" + "=" * 70)
    print("TEST 4: Generating SHAP Summary Plot")
    print("=" * 70)
    
    test_samples = [
        ("SQL Injection", "def get_user(u): cursor.execute('SELECT * WHERE name=' + u)"),
        ("Command Injection", "def ping(h): os.system('ping ' + h)"),
        ("Eval Usage", "def f(x): return eval(x)"),
        ("Safe SQL", "def safe(u): cursor.execute('SELECT * WHERE name=?', (u,))"),
        ("Path Traversal", "def read(f): return open('/var/www/' + f).read()"),
    ]
    
    codes = [code for _, code in test_samples]
    success = generate_shap_plot(codes)
    
    # Summary
    print("\n" + "=" * 70)
    print("✅ PART 6 COMPLETE - SHAP EXPLAINABILITY WORKING!")
    print("=" * 70)
    print(f"Models loaded from: {MODEL_DIR}")
    print(f"Plots saved to: {NOTEBOOKS_DIR}")
    print("\nAvailable functions:")
    print("  • explain_prediction(code)      - Explain single prediction")
    print("  • generate_shap_plot(codes)       - Create SHAP visualization")
    print("  • explain_batch([(name, code)])   - Batch explanations")
    print("=" * 70)