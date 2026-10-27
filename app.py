from pathlib import Path
import csv
import io
import secrets
import sqlite3
import string
from datetime import datetime, timezone

from flask import Flask, flash, redirect, render_template, request, url_for, Response

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "audit.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-before-deployment"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

REQUIRED_COLUMNS = {"username", "password", "profile"}
DIGITS = string.digits

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
        rows.append({"line": line_no, "username": username, "profile": profile, "issues": issues})
        for issue in issues:
            findings.append({"line": line_no, "username": username or "—", "issue": issue})
    try:
        text.detach()
    except Exception:
        pass
    return rows, findings

def random_code(prefix, digits, used):
    alphabet = DIGITS
    for _ in range(10000):
        code = prefix + "".join(secrets.choice(alphabet) for _ in range(digits))
        if code not in used:
            used.add(code)
            return code
    raise ValueError("تعذر إنشاء رموز فريدة بهذه الإعدادات. زد عدد الخانات أو غيّر البادئة.")

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

@app.route("/generate", methods=["POST"])
def generate_csv():
    try:
        count = int(request.form.get("count", "0"))
        digits = int(request.form.get("digits", "6"))
        prefix = request.form.get("prefix", "").strip()
        profile = request.form.get("profile", "default").strip() or "default"
        if not 1 <= count <= 5000:
            raise ValueError("عدد البطاقات يجب أن يكون بين 1 و5000.")
        if not 4 <= digits <= 12:
            raise ValueError("عدد الخانات الرقمية يجب أن يكون بين 4 و12.")
        if len(prefix) > 12 or any(ch not in string.ascii_letters + string.digits + "-_" for ch in prefix):
            raise ValueError("البادئة تقبل أحرفًا إنجليزية وأرقامًا وشرطة أو شرطة سفلية فقط، وبحد أقصى 12 حرفًا.")
        if len(profile) > 64 or any(ord(ch) < 32 for ch in profile):
            raise ValueError("اسم Profile غير صالح.")
        username_used, password_used = set(), set()
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["username", "password", "profile"])
        for _ in range(count):
            username = random_code(prefix, digits, username_used)
            password = random_code("", digits + 2, password_used)
            writer.writerow([username, password, profile])
        payload = "\ufeff" + output.getvalue()
        return Response(
            payload,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="hotspot_cards_generated.csv"'}
        )
    except (ValueError, TypeError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

@app.route("/health")
def health():
    return {"status": "ok", "app": "Hotspot Security Tester"}

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
