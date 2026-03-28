import ast
import re

def extract_features(code_string):
    """Takes Python code as a string, returns a dictionary of features."""
    features = {}

    # --- Feature 1: Dangerous function calls ---
    dangerous_functions = ['eval', 'exec', 'os.system', 'subprocess.call',
                           'subprocess.Popen', 'input', '__import__']
    for func in dangerous_functions:
        features[f'uses_{func.replace(".", "_")}'] = 1 if func in code_string else 0

    # --- Feature 2: SQL injection patterns ---
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
    features['has_sql'] = 1 if any(kw in code_string.upper() for kw in sql_keywords) else 0
    features['has_string_concat_sql'] = 1 if (features['has_sql'] and ('+' in code_string or '%s' in code_string)) else 0

    # --- Feature 3: AST node counts ---
    try:
        tree = ast.parse(code_string)
        node_counts = {}
        for node in ast.walk(tree):
            node_type = type(node).__name__
            node_counts[node_type] = node_counts.get(node_type, 0) + 1
        
        # Key AST nodes that matter for security
        for node_type in ['Call', 'Import', 'Attribute', 'Subscript', 'BinOp']:
            features[f'ast_{node_type}'] = node_counts.get(node_type, 0)
    except SyntaxError:
        for node_type in ['Call', 'Import', 'Attribute', 'Subscript', 'BinOp']:
            features[f'ast_{node_type}'] = 0

    # --- Feature 4: Code length ---
    features['line_count'] = len(code_string.split('\n'))
    features['char_count'] = len(code_string)

    return features


# Test it
if __name__ == "__main__":
    test_code = """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
"""
    print(extract_features(test_code))