from pathlib import Path
import csv
import io
import secrets
import sqlite3
import string
from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
import requests

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

@app.route("/combination-count", methods=["POST"])
def combination_count():
    try:
        total_digits = int(request.form.get("total_digits", "6"))
        fixed_prefix = request.form.get("fixed_prefix", "").strip()
        fixed_suffix = request.form.get("fixed_suffix", "").strip()
        if not 1 <= total_digits <= 18:
            raise ValueError("طول الرمز يجب أن يكون بين 1 و18 خانة.")
        if any(ch not in DIGITS for ch in fixed_prefix + fixed_suffix):
            raise ValueError("الأرقام الثابتة يجب أن تحتوي على أرقام من 0 إلى 9 فقط.")
        if len(fixed_prefix) + len(fixed_suffix) > total_digits:
            raise ValueError("مجموع خانات المقدمة والنهاية الثابتتين أكبر من طول الرمز.")
        variable_digits = total_digits - len(fixed_prefix) - len(fixed_suffix)
        possibilities = 10 ** variable_digits
        return render_template(
            "index.html", results=None, history=get_history(),
            combination_summary={
                "total_digits": total_digits, "fixed_prefix": fixed_prefix,
                "fixed_suffix": fixed_suffix, "variable_digits": variable_digits,
                "possibilities": possibilities
            }
        )
    except (ValueError, TypeError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

@app.route("/report-template")
def report_template():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["test_id", "authorized_test_account", "expected_result", "observed_result", "notes"])
    writer.writerow(["TEST-001", "yes/no", "accepted/rejected", "accepted/rejected/not-run", ""])
    return Response(
        "\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="hotspot_authorized_test_report_template.csv"'}
    )

def get_history():
    init_db()
    with sqlite3.connect(DB_PATH) as db:
        return db.execute(
            "SELECT created_at, filename, rows_checked, findings FROM audit_log ORDER BY id DESC LIMIT 10"
        ).fetchall()

@app.route("/router-check", methods=["POST"])
def router_check():
    uploaded = request.files.get("router_csv")
    base_url = request.form.get("router_url", "").strip().rstrip("/")
    api_user = request.form.get("api_user", "").strip()
    api_password = request.form.get("api_password", "")
    if not uploaded or not uploaded.filename or not uploaded.filename.lower().endswith(".csv"):
        flash("اختر ملف CSV صحيحًا للتحقق من أسماء المستخدمين.", "error")
        return redirect(url_for("index"))
    if not base_url or not api_user or not api_password:
        flash("أدخل عنوان الراوتر واسم مستخدم API وكلمة مروره.", "error")
        return redirect(url_for("index"))
    try:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("أدخل عنوانًا مثل https://192.168.88.1 دون مسار إضافي.")
        host = parsed.hostname
        try:
            addr = ipaddress.ip_address(host)
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                raise ValueError("لأمان الاتصال، يجب أن يكون عنوان الراوتر عنوانًا محليًا/خاصًا.")
        except ValueError as ip_error:
            if "لأمان الاتصال" in str(ip_error):
                raise
            if not (host.endswith(".local") or host == "localhost"):
                raise ValueError("استخدم عنوان IP خاصًا للراوتر أو اسمًا محليًا ينتهي بـ .local.")
        text_stream = io.TextIOWrapper(uploaded.stream, encoding="utf-8-sig", newline="")
        reader = csv.DictReader(text_stream)
        if not reader.fieldnames or "username" not in {name.strip().lower() for name in reader.fieldnames if name}:
            raise ValueError("يجب أن يحتوي CSV على عمود username.")
        usernames = []
        for raw in reader:
            row = {str(k).strip().lower(): (v or "").strip() for k, v in raw.items() if k}
            if row.get("username"):
                usernames.append(row["username"])
        try:
            text_stream.detach()
        except Exception:
            pass
        if not usernames:
            raise ValueError("لم يتم العثور على أسماء مستخدمين في الملف.")
        if len(usernames) > 5000:
            raise ValueError("الحد الأقصى 5000 اسم مستخدم في الملف.")
        if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1"}:
            # RouterOS REST credentials are sent only to the explicitly supplied LAN router.
            pass
        response = requests.get(
            base_url + "/rest/ip/hotspot/user",
            auth=(api_user, api_password),
            headers={"Accept": "application/json"},
            timeout=(4, 12),
            verify=True,
            allow_redirects=False,
        )
        if response.status_code in (301, 302, 303, 307, 308):
            raise ValueError("الراوتر أعاد تحويلًا؛ استخدم عنوان HTTPS الصحيح مباشرة.")
        if response.status_code == 401:
            raise ValueError("رفض الراوتر بيانات API. تحقق من اسم المستخدم وكلمة المرور وصلاحيات القراءة.")
        if response.status_code == 403:
            raise ValueError("حساب API لا يملك صلاحية قراءة مستخدمي Hotspot.")
        response.raise_for_status()
        router_users = response.json()
        if not isinstance(router_users, list):
            raise ValueError("استجابة الراوتر غير متوقعة. تأكد من إصدار RouterOS ودعم REST API.")
        known = {}
        for item in router_users:
            if isinstance(item, dict) and item.get("name"):
                known[str(item["name"])] = item
        checked = []
        for username in usernames:
            item = known.get(username)
            if item is None:
                status = "غير موجود في قائمة المستخدمين"
                css = "issue"
            elif str(item.get("disabled", "false")).lower() in {"true", "yes"}:
                status = "موجود لكنه معطّل"
                css = "issue"
            else:
                status = "موجود ومفعّل (لم تُختبر كلمة المرور)"
                css = "ok"
            checked.append({"username": username, "status": status, "css": css})
        router_results = {"rows": checked, "total": len(checked),
                          "present": sum(1 for x in checked if x["status"].startswith("موجود ومفعّل")),
                          "missing": sum(1 for x in checked if x["status"].startswith("غير موجود")),
                          "disabled": sum(1 for x in checked if x["status"].startswith("موجود لكنه"))}
        init_db()
        with sqlite3.connect(DB_PATH) as db:
            db.execute(
                "INSERT INTO audit_log(created_at, filename, rows_checked, findings) VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), "router-check:" + uploaded.filename[:170],
                 len(checked), router_results["missing"] + router_results["disabled"]),
            )
        with sqlite3.connect(DB_PATH) as db:
            history = db.execute(
                "SELECT created_at, filename, rows_checked, findings FROM audit_log ORDER BY id DESC LIMIT 10"
            ).fetchall()
        return render_template("index.html", results=None, history=history, router_results=router_results)
    except requests.exceptions.SSLError:
        flash("فشل التحقق من شهادة HTTPS. لا تعطّل التحقق من الشهادة؛ استخدم شهادة موثوقة أو عنوان الراوتر الصحيح.", "error")
    except requests.exceptions.Timeout:
        flash("انتهت مهلة الاتصال. تحقق من الشبكة وتفعيل REST API في الراوتر.", "error")
    except requests.exceptions.ConnectionError:
        flash("تعذر الاتصال بالراوتر. تحقق من عنوانه وإتاحة REST API ومن قواعد الجدار الناري.", "error")
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        flash("أعاد RouterOS خطأ HTTP: " + str(code), "error")
    except (ValueError, UnicodeDecodeError, csv.Error, requests.exceptions.RequestException) as exc:
        flash(str(exc) or "حدث خطأ أثناء التحقق.", "error")
    return redirect(url_for("index"))

@app.route("/lab-rate-limit-check", methods=["POST"])
def lab_rate_limit_check():
    """Low-impact HTTP behavior probe for a local lab; does not submit credentials."""
    import time
    target = request.form.get("probe_url", "").strip()
    repetitions_raw = request.form.get("probe_repetitions", "3")
    delay_raw = request.form.get("probe_delay", "2")
    if not target:
        flash("أدخل عنوان صفحة اختبار غير محمية في معملك.", "error")
        return redirect(url_for("index"))
    try:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("أدخل رابط HTTP/HTTPS صحيحًا دون بيانات دخول مضمّنة.")
        host = parsed.hostname
        try:
            addr = ipaddress.ip_address(host)
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                raise ValueError("يُسمح فقط بعنوان IP خاص/محلي للمعمل.")
        except ValueError as ip_error:
            if "يُسمح فقط" in str(ip_error):
                raise
            if host != "localhost" and not host.endswith(".local"):
                raise ValueError("استخدم عنوان IP خاصًا أو اسم مضيف محلي ينتهي بـ .local.")
        repetitions = int(repetitions_raw)
        delay_seconds = float(delay_raw)
        if not 1 <= repetitions <= 10:
            raise ValueError("عدد الطلبات يجب أن يكون من 1 إلى 10.")
        if not 1 <= delay_seconds <= 10:
            raise ValueError("التأخير يجب أن يكون من ثانية إلى 10 ثوانٍ.")
        observations = []
        with requests.Session() as session:
            for i in range(repetitions):
                if i:
                    time.sleep(delay_seconds)
                started = time.monotonic()
                try:
                    response = session.get(target, timeout=(3, 8), allow_redirects=False, verify=True)
                    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
                    if response.status_code == 429:
                        note = "HTTP 429: تقييد طلبات محتمل"
                    elif response.status_code in (301, 302, 303, 307, 308):
                        note = "إعادة توجيه؛ افحص Location"
                    elif response.status_code in (401, 403):
                        note = "رفض وصول؛ راجع سياسة الوصول"
                    else:
                        note = "استجابة مرصودة؛ ليست اختبارًا لتسجيل الدخول"
                    observations.append({"number": i + 1, "status": response.status_code,
                                         "elapsed_ms": elapsed_ms,
                                         "location": response.headers.get("Location", "")[:300],
                                         "note": note})
                except requests.exceptions.RequestException as exc:
                    observations.append({"number": i + 1, "status": "NETWORK_ERROR",
                                         "elapsed_ms": "", "location": "",
                                         "note": type(exc).__name__})
        now = datetime.now(timezone.utc).isoformat()
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["timestamp_utc", "target", "request_number", "http_status", "elapsed_ms", "location", "observation"])
        for item in observations:
            writer.writerow([now, target, item["number"], item["status"], item["elapsed_ms"], item["location"], item["note"]])
        payload = "\\ufeff" + output.getvalue()
        init_db()
        with sqlite3.connect(DB_PATH) as db:
            db.execute(
                "INSERT INTO audit_log(created_at, filename, rows_checked, findings) VALUES (?, ?, ?, ?)",
                (now, "lab-rate-limit:" + host, len(observations),
                 sum(1 for item in observations if item["status"] == 429)),
            )
        return Response(payload, mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="hotspot_lab_rate_limit_report.csv"'})
    except (ValueError, TypeError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

@app.route("/health")
def health():
    return {"status": "ok", "app": "Hotspot Security Tester"}

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
