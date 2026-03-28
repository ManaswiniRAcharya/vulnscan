import ast
import re
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import os

# ─── Rule-based features ───────────────────────────────────────────────
def extract_manual_features(code_string):
    """Extract security-relevant features from Python code."""
    features = {}

    # Dangerous function calls
    dangerous = ['eval', 'exec', 'os.system', 'subprocess.call',
                 'subprocess.Popen', '__import__', 'os.popen',
                 'compile', 'input']
    for func in dangerous:
        key = f'uses_{func.replace(".", "_").replace("(", "")}'
        features[key] = 1 if func in code_string else 0

    # SQL injection patterns
    sql_kw = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']
    features['has_sql'] = 1 if any(k in code_string.upper() for k in sql_kw) else 0
    features['has_string_concat_sql'] = 1 if (
        features['has_sql'] and
        ('+' in code_string or '%s' in code_string or "f'" in code_string or 'f"' in code_string)
    ) else 0
    features['uses_parameterized_query'] = 1 if ('?' in code_string or '%s' in code_string) and 'execute' in code_string else 0

    # Path traversal patterns
    features['has_file_open'] = 1 if 'open(' in code_string else 0
    features['has_path_concat'] = 1 if (features['has_file_open'] and '+' in code_string) else 0
    features['uses_os_path_join'] = 1 if 'os.path.join' in code_string else 0
    features['uses_os_basename'] = 1 if 'os.path.basename' in code_string else 0

    # XSS patterns
    features['has_html_output'] = 1 if any(t in code_string for t in ['<p>', '<h1>', '<div>', '<span>', 'innerHTML']) else 0
    features['uses_html_escape'] = 1 if ('escape(' in code_string or 'html.escape' in code_string) else 0

    # Shell usage
    features['uses_shell_true'] = 1 if 'shell=True' in code_string else 0
    features['uses_shell_false'] = 1 if 'shell=False' in code_string else 0

    # AST-based features
    try:
        tree = ast.parse(code_string)
        node_counts = {}
        for node in ast.walk(tree):
            node_type = type(node).__name__
            node_counts[node_type] = node_counts.get(node_type, 0) + 1

        for node_type in ['Call', 'Import', 'ImportFrom', 'Attribute',
                          'Subscript', 'BinOp', 'JoinedStr', 'FunctionDef']:
            features[f'ast_{node_type}'] = node_counts.get(node_type, 0)
    except SyntaxError:
        for node_type in ['Call', 'Import', 'ImportFrom', 'Attribute',
                          'Subscript', 'BinOp', 'JoinedStr', 'FunctionDef']:
            features[f'ast_{node_type}'] = 0

    # Code stats
    features['line_count'] = len(code_string.split('\n'))
    features['char_count'] = len(code_string)

    return features


# ─── TF-IDF on code tokens ─────────────────────────────────────────────
def tokenize_code(code_string):
    """Convert code to a simple token string for TF-IDF."""
    # Split on non-alphanumeric chars, keep meaningful tokens
    tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', code_string)
    return ' '.join(tokens)


def build_feature_matrix(codes, tfidf_vectorizer=None, fit=False):
    """
    Takes a list of code strings.
    Returns (feature_matrix, tfidf_vectorizer)
    Set fit=True when building training data, fit=False when predicting.
    """
    # Manual features
    manual = pd.DataFrame([extract_manual_features(c) for c in codes])

    # TF-IDF features on code tokens
    token_strings = [tokenize_code(c) for c in codes]

    if fit:
        tfidf_vectorizer = TfidfVectorizer(max_features=50, ngram_range=(1, 2))
        tfidf_matrix = tfidf_vectorizer.fit_transform(token_strings).toarray()
    else:
        tfidf_matrix = tfidf_vectorizer.transform(token_strings).toarray()

    tfidf_df = pd.DataFrame(tfidf_matrix,
                            columns=[f'tfidf_{i}' for i in range(tfidf_matrix.shape[1])])

    # Combine both
    combined = pd.concat([manual.reset_index(drop=True),
                          tfidf_df.reset_index(drop=True)], axis=1)
    return combined, tfidf_vectorizer


# Test it standalone
if __name__ == "__main__":
    test_codes = [
        "def get_user(u): cursor.execute('SELECT * FROM users WHERE name=' + u)",
        "def get_user(u): cursor.execute('SELECT * FROM users WHERE name=?', (u,))",
        "def ping(h): os.system('ping ' + h)",
    ]
    features, vectorizer = build_feature_matrix(test_codes, fit=True)
    print("Feature matrix shape:", features.shape)
    print("Columns:", list(features.columns[:10]), "...")
    print("\nSample row (SQL injection code):")
    print(features.iloc[0][['has_sql', 'has_string_concat_sql', 'uses_parameterized_query', 'uses_os_system']])