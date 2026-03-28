import csv
import os

# Each entry: (code_snippet, cwe_label, is_vulnerable)
# 1 = vulnerable, 0 = safe/clean

data = [

    # ===== CWE-89: SQL Injection =====
    ("""def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)""", "CWE-89", 1),

    ("""def get_product(pid):
    sql = "SELECT * FROM products WHERE id = " + str(pid)
    db.execute(sql)""", "CWE-89", 1),

    ("""def login(user, pwd):
    q = "SELECT * FROM accounts WHERE user='%s' AND pwd='%s'" % (user, pwd)
    cursor.execute(q)""", "CWE-89", 1),

    ("""def search_items(keyword):
    query = f"SELECT * FROM items WHERE name = '{keyword}'"
    conn.execute(query)""", "CWE-89", 1),

    ("""def delete_record(record_id):
    cursor.execute("DELETE FROM records WHERE id = " + record_id)""", "CWE-89", 1),

    # Safe SQL versions
    ("""def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (username,))""", "SAFE", 0),

    ("""def login(user, pwd):
    cursor.execute("SELECT * FROM accounts WHERE user=? AND pwd=?", (user, pwd))""", "SAFE", 0),

    ("""def get_product(pid):
    cursor.execute("SELECT * FROM products WHERE id = %s", (pid,))""", "SAFE", 0),

    # ===== CWE-78: OS Command Injection =====
    ("""def ping_host(host):
    os.system("ping " + host)""", "CWE-78", 1),

    ("""def list_files(directory):
    os.system("ls " + directory)""", "CWE-78", 1),

    ("""def run_script(name):
    subprocess.call("python " + name, shell=True)""", "CWE-78", 1),

    ("""def delete_file(filename):
    os.system("rm " + filename)""", "CWE-78", 1),

    ("""def compress(folder):
    os.popen("zip -r output.zip " + folder)""", "CWE-78", 1),

    # Safe command versions
    ("""def ping_host(host):
    subprocess.run(["ping", host], shell=False)""", "SAFE", 0),

    ("""def list_files(directory):
    import os
    return os.listdir(directory)""", "SAFE", 0),

    ("""def run_script(name):
    subprocess.run(["python", name], shell=False)""", "SAFE", 0),

    # ===== CWE-20: Improper Input Validation =====
    ("""def calculate(expr):
    result = eval(expr)
    return result""", "CWE-20", 1),

    ("""def run_code(code_str):
    exec(code_str)""", "CWE-20", 1),

    ("""def load_module(name):
    mod = __import__(name)
    return mod""", "CWE-20", 1),

    ("""def dynamic_eval(user_input):
    return eval(user_input, {}, {})""", "CWE-20", 1),

    # Safe validation versions
    ("""def calculate(expr):
    allowed = set('0123456789+-*/(). ')
    if not all(c in allowed for c in expr):
        raise ValueError("Invalid expression")
    return eval(expr)""", "SAFE", 0),

    ("""def get_age(value):
    if not isinstance(value, int) or value < 0 or value > 150:
        raise ValueError("Invalid age")
    return value""", "SAFE", 0),

    # ===== CWE-22: Path Traversal =====
    ("""def read_file(filename):
    with open("/var/www/" + filename) as f:
        return f.read()""", "CWE-22", 1),

    ("""def serve_file(path):
    full_path = base_dir + path
    return open(full_path).read()""", "CWE-22", 1),

    ("""def load_template(name):
    return open("templates/" + name).read()""", "CWE-22", 1),

    # Safe path versions
    ("""def read_file(filename):
    safe_name = os.path.basename(filename)
    full_path = os.path.join("/var/www/", safe_name)
    with open(full_path) as f:
        return f.read()""", "SAFE", 0),

    ("""def serve_file(path):
    safe = os.path.realpath(path)
    if not safe.startswith(base_dir):
        raise PermissionError("Access denied")
    return open(safe).read()""", "SAFE", 0),

    # ===== CWE-79: XSS =====
    ("""def show_comment(comment):
    return "<p>" + comment + "</p>" """, "CWE-79", 1),

    ("""def render_username(name):
    html = f"<h1>Welcome {name}</h1>"
    return html""", "CWE-79", 1),

    ("""def display_message(msg):
    return "<div class='message'>" + msg + "</div>" """, "CWE-79", 1),

    # Safe XSS versions
    ("""def show_comment(comment):
    from html import escape
    return "<p>" + escape(comment) + "</p>" """, "SAFE", 0),

    ("""def render_username(name):
    from html import escape
    return f"<h1>Welcome {escape(name)}</h1>" """, "SAFE", 0),

    # ===== More safe generic code =====
    ("""def add(a, b):
    return a + b""", "SAFE", 0),

    ("""def read_config():
    with open("config.json") as f:
        return json.load(f)""", "SAFE", 0),

    ("""def hash_password(pwd):
    import hashlib
    return hashlib.sha256(pwd.encode()).hexdigest()""", "SAFE", 0),

    ("""def validate_email(email):
    import re
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))""", "SAFE", 0),

    ("""def connect_db():
    conn = sqlite3.connect('app.db')
    return conn""", "SAFE", 0),
]

# Save to CSV
os.makedirs("../data/raw", exist_ok=True)
output_path = "vulnscan_dataset.csv"

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["code", "cwe_label", "is_vulnerable"])
    for code, label, vuln in data:
        writer.writerow([code, label, vuln])

print(f"Dataset saved! Total samples: {len(data)}")

# Count per label
from collections import Counter
label_counts = Counter(label for _, label, _ in data)
print("Label distribution:")
for label, count in sorted(label_counts.items()):
    print(f"  {label}: {count} samples")