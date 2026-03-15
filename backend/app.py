from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # This allows your React frontend to talk to Flask

@app.route('/')
def home():
    return jsonify({"message": "VulnScan API is running!"})

@app.route('/analyze', methods=['POST'])
def analyze():
    # We'll fill this in Week 3 — for now it returns fake data
    data = request.get_json()
    code = data.get('code', '')
    
    # Fake response (placeholder)
    return jsonify({
        "vulnerabilities": [
            {
                "line_no": 2,
                "cwe_type": "CWE-89",
                "cwe_name": "SQL Injection",
                "confidence": 0.92,
                "suggestion": "Use parameterized queries instead of string formatting"
            }
        ]
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)