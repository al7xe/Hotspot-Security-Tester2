from pathlib import Path
import csv
import io
import sqlite3
from datetime import datetime, timezone

from flask import Flask, flash, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "audit.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-before-deployment"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

REQUIRED_COLUMNS = {"username", "password", "profile"}

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                rows_checked INTEGER NOT NULL,
                findings INTEGER NOT NULL
            )
        """)

def inspect_csv(file_stream):
    text = io.TextIOWrapper(file_stream, encoding="utf-8-sig", newline="")
    reader = csv.DictReader(text)
    if not reader.fieldnames:
        raise ValueError("الملف فارغ أو لا يحتوي على عناوين أعمدة.")
    normalized = {name.strip().lower() for name in reader.fieldnames if name}
    missing = REQUIRED_COLUMNS - normalized
    if missing:
        raise ValueError("الأعمدة المطلوبة غير موجودة: " + ", ".join(sorted(missing)))

    rows = []
    findings = []
    for line_no, raw in enumerate(reader, start=2):
        row = {str(k).strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        username = row.get("username", "")
        password = row.get("password", "")
        profile = row.get("profile", "")
        issues = []
        if not username:
            issues.append("اسم المستخدم فارغ")
        if not password:
            issues.append("كلمة المرور فارغة")
        if username and username.lower() in {"admin", "administrator", "test", "user"}:
            issues.append("اسم مستخدم شائع")
        if password and password.lower() in {"123456", "12345678", "password", "admin", "1234"}:
            issues.append("كلمة مرور شائعة")
        if username and password and username == password:
            issues.append("اسم المستخدم يطابق كلمة المرور")
        if not profile:
            issues.append("الملف التعريفي غير محدد")
        rows.append({
            "line": line_no,
            "username": username,
            "profile": profile,
            "issues": issues,
        })
        for issue in issues:
            findings.append({"line": line_no, "username": username or "—", "issue": issue})
    try:
        text.detach()
    except Exception:
        pass
    return rows, findings

@app.route("/", methods=["GET", "POST"])
def index():
    init_db()
    results = None
    if request.method == "POST":
        uploaded = request.files.get("csv_file")
        if not uploaded or not uploaded.filename:
            flash("اختر ملف CSV أولًا.", "error")
            return redirect(url_for("index"))
        if not uploaded.filename.lower().endswith(".csv"):
            flash("يسمح بملفات CSV فقط.", "error")
            return redirect(url_for("index"))
        try:
            rows, findings = inspect_csv(uploaded.stream)
            with sqlite3.connect(DB_PATH) as db:
                db.execute(
                    "INSERT INTO audit_log(created_at, filename, rows_checked, findings) VALUES (?, ?, ?, ?)",
                    (datetime.now(timezone.utc).isoformat(), uploaded.filename[:200], len(rows), len(findings)),
                )
            results = {"rows": rows, "findings": findings, "total": len(rows), "issues": len(findings)}
        except (ValueError, UnicodeDecodeError, csv.Error) as exc:
            flash(str(exc), "error")
    with sqlite3.connect(DB_PATH) as db:
        history = db.execute(
            "SELECT created_at, filename, rows_checked, findings FROM audit_log ORDER BY id DESC LIMIT 10"
        ).fetchall()
    return render_template("index.html", results=results, history=history)

@app.route("/health")
def health():
    return {"status": "ok", "app": "Hotspot Security Tester"}

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
