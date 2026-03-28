import pickle
import os
import sys
import numpy as np

# Point to the model folder
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'model')

model = None
cwe_model = None
tfidf_vectorizer = None
label_encoder = None

def load_models():
    global model, cwe_model, tfidf_vectorizer, label_encoder
    with open(os.path.join(MODEL_DIR, 'saved_model.pkl'), 'rb') as f:
        model = pickle.load(f)
    with open(os.path.join(MODEL_DIR, 'cwe_model.pkl'), 'rb') as f:
        cwe_model = pickle.load(f)
    with open(os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl'), 'rb') as f:
        tfidf_vectorizer = pickle.load(f)
    with open(os.path.join(MODEL_DIR, 'label_encoder.pkl'), 'rb') as f:
        label_encoder = pickle.load(f)
    print("All models loaded!")

def predict(code_string):
    if model is None:
        load_models()

    # Import features module
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'model'))
    from features import build_feature_matrix

    X, _ = build_feature_matrix([code_string],
                                  tfidf_vectorizer=tfidf_vectorizer,
                                  fit=False)

    # Binary prediction
    is_vulnerable = bool(model.predict(X)[0])
    confidence = float(max(model.predict_proba(X)[0]))

    # CWE type prediction
    cwe_pred = cwe_model.predict(X)[0]
    cwe_label = str(label_encoder.inverse_transform([cwe_pred])[0])
    cwe_confidence = float(max(cwe_model.predict_proba(X)[0]))

    return {
        "is_vulnerable": is_vulnerable,
        "confidence": confidence,
        "cwe_label": cwe_label,
        "cwe_confidence": cwe_confidence,
        "features": X.iloc[0].to_dict()
    }

if __name__ == "__main__":
    load_models()
    result = predict("""
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
""")
    print(result)