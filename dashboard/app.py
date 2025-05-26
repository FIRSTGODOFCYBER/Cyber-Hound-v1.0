from flask import Flask, jsonify, render_template, request, send_file
import sqlite3
import os
from fpdf import FPDF
import io
from datetime import datetime

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "traffic.db")

def query_traffic(start=None, end=None, ip=None, limit=100):
    query = "SELECT timestamp, src_ip, dst_ip, prediction FROM traffic WHERE 1=1"
    params = []

    if start:
        query += " AND timestamp >= ?"
        params.append(start)
    if end:
        query += " AND timestamp <= ?"
        params.append(end)
    if ip:
        query += " AND (src_ip = ? OR dst_ip = ?)"
        params.extend([ip, ip])

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/data")
def data():
    start = request.args.get("start")
    end = request.args.get("end")
    ip = request.args.get("ip")
    try:
        rows = query_traffic(start=start, end=end, ip=ip, limit=100)
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/export", methods=["POST"])
def export_pdf():
    start = request.form.get("start")
    end = request.form.get("end")
    ip = request.form.get("ip")

    try:
        rows = query_traffic(start=start, end=end, ip=ip, limit=1000)

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Network Traffic Report", ln=1, align="C")
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)

        pdf.set_fill_color(200, 200, 200)
        pdf.cell(50, 10, "Timestamp", 1, 0, 'C', 1)
        pdf.cell(40, 10, "Source IP", 1, 0, 'C', 1)
        pdf.cell(40, 10, "Dest IP", 1, 0, 'C', 1)
        pdf.cell(30, 10, "Prediction", 1, 1, 'C', 1)

        pdf.set_font("Arial", "", 10)
        for row in rows:
            pred = "Attack" if row[3] == 1 else "Benign"
            pdf.cell(50, 8, str(row[0]), 1)
            pdf.cell(40, 8, row[1], 1)
            pdf.cell(40, 8, row[2], 1)
            pdf.cell(30, 8, pred, 1, ln=1)

        pdf_buffer = io.BytesIO()
        pdf.output(pdf_buffer)
        pdf_buffer.seek(0)

        return send_file(pdf_buffer, download_name="filtered_report.pdf", as_attachment=True)
    except Exception as e:
        return f"Error generating PDF: {e}", 500

if __name__ == "__main__":
    app.run(debug=True)
