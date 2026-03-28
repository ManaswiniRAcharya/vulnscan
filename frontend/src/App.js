import { useState } from "react";
import Editor from "@monaco-editor/react";
import axios from "axios";

const CWE_COLORS = {
  "CWE-89": "#dc2626",
  "CWE-78": "#ea580c",
  "CWE-22": "#d97706",
  "CWE-79": "#7c3aed",
  "CWE-20": "#0891b2",
};

function App() {
  const [code, setCode] = useState(`def get_user(username):\n    query = "SELECT * FROM users WHERE name = '" + username + "'"\n    cursor.execute(query)\n`);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState("scan"); // "scan" or "history"
  const [history, setHistory] = useState([]);

  const analyzeCode = async () => {
    setLoading(true);
    try {
      const response = await axios.post("http://localhost:5000/analyze", { code });
      setResults(response.data.vulnerabilities);
    } catch (e) {
      alert("Backend not reachable. Make sure Flask is running on port 5000.");
    }
    setLoading(false);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (!file.name.endsWith(".py")) {
      alert("Please upload a .py Python file");
      return;
    }
    const reader = new FileReader();
    reader.onload = (event) => setCode(event.target.result);
    reader.readAsText(file);
  };

  const loadHistory = async () => {
    setTab("history");
    const response = await axios.get("http://localhost:5000/history");
    setHistory(response.data);
  };

  return (
    <div style={{ fontFamily: "sans-serif", maxWidth: "1100px", margin: "0 auto", padding: "20px" }}>
      <h1>🔐 VulnScan</h1>
      <p style={{ color: "#555" }}>Real-time Python vulnerability detection with CWE classification</p>

      {/* Tabs */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "20px" }}>
        {["scan", "history"].map((t) => (
          <button key={t} onClick={() => t === "history" ? loadHistory() : setTab("scan")}
            style={{
              padding: "8px 20px", borderRadius: "6px", border: "none",
              backgroundColor: tab === t ? "#4f46e5" : "#e5e7eb",
              color: tab === t ? "white" : "#333", cursor: "pointer", fontWeight: "bold"
            }}>
            {t === "scan" ? "🔍 Scan Code" : "📋 History"}
          </button>
        ))}
      </div>

      {tab === "scan" && (
        <>
          {/* File upload */}
          <div style={{ marginBottom: "12px" }}>
            <label style={{ cursor: "pointer", backgroundColor: "#f3f4f6", padding: "8px 16px", borderRadius: "6px", border: "1px solid #d1d5db" }}>
              📁 Upload .py file  <input type="file" accept=".py" onChange={handleFileUpload} style={{ display: "none" }} />
            </label>
            <span style={{ color: "#888", marginLeft: "12px", fontSize: "13px" }}>or paste your code below</span>
          </div>

          {/* Editor */}
          <div style={{ border: "1px solid #d1d5db", borderRadius: "8px", overflow: "hidden", marginBottom: "16px" }}>
            <Editor
              height="280px"
              language="python"
              value={code}
              onChange={(v) => setCode(v)}
              theme="vs-dark"
              options={{ fontSize: 14, minimap: { enabled: false } }}
            />
          </div>

          <button onClick={analyzeCode} disabled={loading}
            style={{ backgroundColor: "#4f46e5", color: "white", padding: "10px 28px", border: "none", borderRadius: "6px", fontSize: "16px", cursor: "pointer" }}>
            {loading ? "⏳ Scanning..." : "🔍 Scan for Vulnerabilities"}
          </button>

          {/* Results */}
          {results !== null && (
            <div style={{ marginTop: "28px" }}>
              <h2>Scan Results</h2>
              {results.length === 0 ? (
                <div style={{ backgroundColor: "#f0fdf4", border: "1px solid #86efac", borderRadius: "8px", padding: "16px" }}>
                  ✅ <strong>No vulnerabilities detected!</strong>
                </div>
              ) : (
                <div>
                  <p style={{ color: "#dc2626", fontWeight: "bold" }}>⚠️ {results.length} vulnerability(ies) found</p>
                  {results.map((vuln, i) => (
                    <div key={i} style={{ border: `1px solid ${CWE_COLORS[vuln.cwe_type] || "#f87171"}`, borderLeft: `5px solid ${CWE_COLORS[vuln.cwe_type] || "#f87171"}`, borderRadius: "8px", padding: "16px", marginBottom: "12px", backgroundColor: "#fef2f2" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontWeight: "bold", color: CWE_COLORS[vuln.cwe_type] }}>🔴 {vuln.cwe_type}: {vuln.cwe_name}</span>
                        <span style={{ backgroundColor: "#fee2e2", color: "#991b1b", padding: "2px 10px", borderRadius: "12px", fontSize: "13px" }}>
                          Line {vuln.line_no}
                        </span>
                      </div>
                      <div style={{ marginTop: "8px" }}>
                        <strong>Confidence:</strong>
                        <div style={{ backgroundColor: "#e5e7eb", borderRadius: "4px", height: "8px", marginTop: "4px" }}>
                          <div style={{ width: `${(vuln.confidence * 100).toFixed(0)}%`, backgroundColor: CWE_COLORS[vuln.cwe_type], height: "100%", borderRadius: "4px" }} />
                        </div>
                        <span style={{ fontSize: "12px", color: "#555" }}>{(vuln.confidence * 100).toFixed(0)}%</span>
                      </div>
                      <div style={{ marginTop: "10px", backgroundColor: "#fffbeb", border: "1px solid #fcd34d", borderRadius: "6px", padding: "10px" }}>
                        💡 <strong>Fix suggestion:</strong><br />
                        <span style={{ fontSize: "14px" }}>{vuln.suggestion}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {tab === "history" && (
        <div>
          <h2>Scan History (last 20)</h2>
          {history.length === 0 ? <p>No scans yet.</p> : history.map((scan) => (
            <div key={scan.id} style={{ border: "1px solid #e5e7eb", borderRadius: "8px", padding: "12px", marginBottom: "8px" }}>
              <code style={{ fontSize: "12px", color: "#555" }}>{scan.code_preview}</code>
              <div style={{ marginTop: "6px", fontSize: "13px" }}>
                {scan.vulnerabilities.length === 0
                  ? <span style={{ color: "green" }}>✅ Clean</span>
                  : <span style={{ color: "red" }}>⚠️ {scan.vulnerabilities.length} issue(s) — {scan.vulnerabilities.map(v => v.cwe_type).join(", ")}</span>}
                <span style={{ color: "#aaa", marginLeft: "12px" }}>{scan.created_at}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;
