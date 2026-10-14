from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import sqlite3
import pandas as pd
import os
from models.database import get_db_connection, init_db
from services.ioc_validator import validate_indicator
from services.risk_engine import calculate_threat_risk, classify_risk_tier

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/dashboard")
def dashboard_page():
    return send_from_directory(app.static_folder, "threat-dashboard.html")

@app.route("/awareness")
def awareness_page():
    return send_from_directory(app.static_folder, "awareness.html")

@app.route("/quiz")
def quiz_page():
    return send_from_directory(app.static_folder, "quiz.html")

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    total_threats = cursor.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    critical_threats = cursor.execute("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'").fetchone()[0]
    high_threats = cursor.execute("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'").fetchone()[0]
    active_indicators = cursor.execute("SELECT COUNT(DISTINCT indicator_value) FROM threats").fetchone()[0]
    open_investigations = cursor.execute("SELECT COUNT(*) FROM threats WHERE status = 'NEW' OR status = 'UNDER_REVIEW'").fetchone()[0]
    avg_conf = cursor.execute("SELECT AVG(confidence_score) FROM threats").fetchone()[0] or 0
    vulnerabilities = cursor.execute("SELECT COUNT(*) FROM threats WHERE category = 'VULNERABILITY EXPOSURE'").fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "active_indicators": active_indicators,
        "open_investigations": open_investigations,
        "average_confidence": round(avg_conf, 1),
        "vulnerabilities_tracked": vulnerabilities
    })

@app.route("/api/threats", methods=["GET"])
def get_threats():
    conn = get_db_connection()
    severity = request.args.get("severity")
    category = request.args.get("category")
    status = request.args.get("status")
    
    query = "SELECT * FROM threats WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if category:
        query += " AND category = ?"
        params.append(category)
    if status:
        query += " AND status = ?"
        params.append(status)
        
    query += " ORDER BY risk_score DESC LIMIT 100"
    
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return jsonify(df.to_dict(orient="records"))

@app.route("/api/indicators/search", methods=["GET"])
def search_indicator():
    val = request.args.get("value", "").strip().lower()
    if not val:
        return jsonify({"error": "No search indicator provided"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    record = cursor.execute("SELECT * FROM threats WHERE indicator_value LIKE ?", (f"%{val}%",)).fetchone()
    conn.close()
    
    if not record:
        return jsonify({"found": False, "message": "Indicator not present in local threat dataset."})
        
    return jsonify({
        "found": True,
        "threat_id": record["threat_id"],
        "threat_name": record["threat_name"],
        "indicator_type": record["indicator_type"],
        "indicator_value": record["indicator_value"],
        "severity": record["severity"],
        "risk_score": record["risk_score"],
        "confidence_score": record["confidence_score"],
        "category": record["category"],
        "first_seen": record["first_seen"],
        "last_seen": record["last_seen"],
        "status": record["status"],
        "mitre_tactic": record["mitre_tactic"],
        "mitre_technique": record["mitre_technique"]
    })

@app.route("/api/quiz/submit", methods=["POST"])
def submit_quiz():
    data = request.json
    score = data.get("score", 0)
    category_breakdown = data.get("categories", {})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO quiz_results (overall_score, category_scores, created_at) VALUES (?, ?, datetime('now'))",
        (score, str(category_breakdown))
    )
    conn.commit()
    conn.close()
    
    recommendation = "Strong Awareness" if score >= 80 else ("Good Awareness" if score >= 60 else "Review Security Modules")
    return jsonify({"success": True, "score": score, "recommendation": recommendation})

if __name__ == "__main__":
    init_db()
    # Import CSV data into SQLite if table is empty
    conn = get_db_connection()
    cursor = conn.cursor()
    count = cursor.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    if count == 0 and os.path.exists("data/threat_intelligence_dataset.csv"):
        print("[+] Importing synthetic dataset into SQLite...")
        df = pd.read_csv("data/threat_intelligence_dataset.csv")
        df.to_sql("threats", conn, if_exists="append", index=False)
        print(f"[+] Imported {len(df)} records into database.")
    conn.close()
    
    app.run(debug=True, port=5000)
