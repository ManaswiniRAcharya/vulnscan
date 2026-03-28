from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import json

app = Flask(__name__)
CORS(app)

CWE_SUGGESTIONS = {
    "CWE-89": "Use parameterized queries. Replace: cursor.execute('SELECT * WHERE id=' + x) with cursor.execute('SELECT * WHERE id=?', (x,))",
    "CWE-78": "Avoid os.system(). Use subprocess.run(['command', 'arg'], shell=False) instead.",
    "CWE-22": "Validate and sanitize file paths. Use os.path.basename() and never trust user input for file paths.",
    "CWE-79": "Escape all user input before rendering HTML. Use a templating engine with auto-escaping.",
    "CWE-20": "Validate all inputs. Check type, length, format, and range before using.",
}

def get_db():
    db = sqlite3.connect('vulnscan_history.db')
    db.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        result TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    db.commit()
    return db

def detect_line(code, keywords):
    for i, line in enumerate(code.split('\n'), start=1):
        if any(kw in line for kw in keywords):
            return i
    return 1

@app.route('/')
def home():
    return jsonify({"message": "VulnScan API is running!"})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    code = data.get('code', '')

    if not code.strip():
        return jsonify({"error": "No code provided"}), 400

    from preprocessing import extract_features
    features = extract_features(code)

    try:
        from inference import predict
        result = predict(code)
        confidence = result['confidence']
    except Exception:
        is_vulnerable = any([
            features.get('has_string_concat_sql'),
            features.get('uses_eval'),
            features.get('uses_exec'),
            features.get('uses_os_system'),
        ])
        confidence = 0.88 if is_vulnerable else 0.12

    vulnerabilities = []

    if features.get('has_string_concat_sql'):
        vulnerabilities.append({
            "line_no": detect_line(code, ['SELECT', 'INSERT', 'UPDATE', 'DELETE']),
            "cwe_type": "CWE-89",
            "cwe_name": "SQL Injection",
            "confidence": confidence,
            "suggestion": CWE_SUGGESTIONS["CWE-89"]
        })

    if features.get('uses_os_system'):
        vulnerabilities.append({
            "line_no": detect_line(code, ['os.system']),
            "cwe_type": "CWE-78",
            "cwe_name": "OS Command Injection",
            "confidence": confidence,
            "suggestion": CWE_SUGGESTIONS["CWE-78"]
        })

    if features.get('uses_eval') or features.get('uses_exec'):
        vulnerabilities.append({
            "line_no": detect_line(code, ['eval(', 'exec(']),
            "cwe_type": "CWE-20",
            "cwe_name": "Improper Input Validation",
            "confidence": confidence,
            "suggestion": CWE_SUGGESTIONS["CWE-20"]
        })

    db = get_db()
    db.execute("INSERT INTO scans (code, result) VALUES (?, ?)",
               (code, json.dumps(vulnerabilities)))
    db.commit()
    db.close()

    return jsonify({"vulnerabilities": vulnerabilities})

@app.route('/history', methods=['GET'])
def history():
    db = get_db()
    rows = db.execute("SELECT id, code, result, created_at FROM scans ORDER BY created_at DESC LIMIT 20").fetchall()
    db.close()
    return jsonify([{
        "id": r[0],
        "code_preview": r[1][:80] + "..." if len(r[1]) > 80 else r[1],
        "vulnerabilities": json.loads(r[2]),
        "created_at": r[3]
    } for r in rows])

if __name__ == '__main__':
    app.run(debug=True, port=5000)