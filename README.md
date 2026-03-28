# VulnScan 🔐

A web-based ML tool for real-time Python code vulnerability detection with CWE classification and fix suggestions.

## What it does

VulnScan scans Python code and detects security vulnerabilities using machine learning. It classifies vulnerabilities by CWE type, shows which line is affected, gives a confidence score, and suggests how to fix the issue.

**Detected vulnerability types:**
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-20: Improper Input Validation (eval/exec)
- CWE-22: Path Traversal
- CWE-79: Cross-Site Scripting (XSS)

## What makes this unique

| Feature | Existing tools | VulnScan |
|---|---|---|
| Language | Mostly C/C++ | Python |
| Output | Binary (yes/no) | CWE type + fix suggestion |
| Interface | CLI / research only | Web UI with code editor |
| Explainability | Rarely included | SHAP feature importance |
| Deployment | Local only | Live web app |

## Team

| Role | Responsibilities |
|---|---|
| Person A (ML Engineer) | Dataset, feature engineering, model training, SHAP |
| Person B (Full Stack) | Flask API, React UI, SQLite, deployment |

## Tech Stack

| Layer | Tool |
|---|---|
| ML | scikit-learn, XGBoost, SHAP |
| Feature extraction | Python ast module, TF-IDF |
| Backend API | Flask + Flask-CORS |
| Frontend | React + Monaco Editor |
| Database | SQLite (scan history) |
| Deployment | Render.com + Vercel |

## How to run locally

### 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/vulnscan.git
cd vulnscan

### 2. Install backend dependencies
cd backend
pip install flask flask-cors scikit-learn xgboost shap pandas numpy imbalanced-learn

### 3. Train the model (Person A step)
cd ../data/raw
python build_dataset.py
cd ../../model
python train.py

### 4. Start the backend
cd ../backend
python app.py

### 5. Start the frontend (new terminal)
cd frontend
npm install
npm start

### 6. Open the app
Visit http://localhost:3000

## Sample test cases

Paste this into the editor to test SQL Injection detection:
```python
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
```

Paste this to test Command Injection detection:
```python
import os
def ping_host(host):
    os.system("ping " + host)
```

## Model Performance

- Algorithm: Random Forest Classifier
- Training samples: 37 labeled Python code snippets
- Features: 54 (manual security rules + TF-IDF tokens)
- F1 Score: 0.733
- AUC-ROC: computed per evaluation report

## Project Structure
```
vulnscan/
├── data/raw/           # labeled dataset CSV
├── model/              # training scripts + saved .pkl files
├── backend/            # Flask API
├── frontend/           # React app
└── notebooks/          # evaluation charts
```