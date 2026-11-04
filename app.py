import os
import json
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "").strip()
DATA_FILE = os.environ.get("DATA_FILE", "/tmp/licenses.json")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_days_iso(days):
    d = datetime.now(timezone.utc) + timedelta(days=int(days))
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_code(code):
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def format_code(normalized):
    if not normalized.startswith("DMI") or len(normalized) < 15:
        return normalized
    body = normalized[3:15]
    return f"DMI-{body[0:4]}-{body[4:8]}-{body[8:12]}"


def load_db():
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_db(db):
    folder = os.path.dirname(DATA_FILE)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def make_token(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    payload_b64 = b64url(raw)
    sig = hmac.new(
        LICENSE_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"{payload_b64}.{b64url(sig)}"


def generate_code():
    alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

    def block():
        return "".join(secrets.choice(alphabet) for _ in range(4))

    return f"DMI-{block()}-{block()}-{block()}"


def ok(data, status=200):
    resp = jsonify(data)
    resp.status_code = status
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


def require_admin():
    admin_key = request.headers.get("X-Admin-Key", "")
    return bool(LICENSE_SECRET) and admin_key == LICENSE_SECRET


@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    return ok(
        {
            "ok": True,
            "service": "dmi-license",
            "time": now_iso(),
            "has_secret": bool(LICENSE_SECRET),
        }
    )


@app.route("/activate", methods=["POST", "OPTIONS"])
def activate():
    if request.method == "OPTIONS":
        return ok({"ok": True})
    if not LICENSE_SECRET:
        return ok({"ok": False, "error": "LICENSE_SECRET تنظیم نشده"}, 500)

    body = request.get_json(silent=True) or {}
    code = str(body.get("code") or "").strip()
    machine_id = str(body.get("machine_id") or "").strip()
    if not code or not machine_id or len(machine_id) < 16:
        return ok({"ok": False, "error": "کد و شناسه دستگاه الزامی است"}, 400)

    key = normalize_code(code)
    db = load_db()
    row = db.get(key)
    if not row:
        return ok({"ok": False, "error": "کد فعال‌سازی نامعتبر است"}, 404)
    if row.get("status") == "revoked":
        return ok({"ok": False, "error": "این کد باطل شده است"}, 403)

    if row.get("status") == "active" and row.get("machine_id"):
        if row["machine_id"] != machine_id:
            return ok({"ok": False, "error": "این کد قبلاً روی سیستم دیگری فعال شده است"}, 403)
        if row.get("expires_at") and row["expires_at"] < now_iso():
            row["status"] = "expired"
            db[key] = row
            save_db(db)
            return ok({"ok": False, "error": "اعتبار این کد تمام شده است"}, 403)

        row["last_validate_at"] = now_iso()
        db[key] = row
        save_db(db)
        token = make_token(
            {
                "code": row["code"],
                "machine_id": machine_id,
                "expires_at": row["expires_at"],
                "activated_at": row.get("activated_at"),
                "plan_days": row.get("plan_days"),
                "iat": now_iso(),
            }
        )
        return ok(
            {
                "ok": True,
                "expires_at": row["expires_at"],
                "plan_days": row.get("plan_days"),
                "token": token,
                "server_time": now_iso(),
                "message": "قبلاً روی همین سیستم فعال شده بود",
            }
        )

    if row.get("status") == "expired":
        return ok({"ok": False, "error": "اعتبار این کد تمام شده است"}, 403)

    activated_at = now_iso()
    expires_at = add_days_iso(row.get("plan_days") or 30)
    row.update(
        {
            "status": "active",
            "activated_at": activated_at,
            "expires_at": expires_at,
            "machine_id": machine_id,
            "last_validate_at": activated_at,
            "code": format_code(key),
        }
    )
    hist = row.get("machine_id_history") or []
    hist.append({"id": machine_id, "at": activated_at})
    row["machine_id_history"] = hist
    db[key] = row
    save_db(db)

    token = make_token(
        {
            "code": row["code"],
            "machine_id": machine_id,
            "expires_at": expires_at,
            "activated_at": activated_at,
            "plan_days": row.get("plan_days"),
            "iat": now_iso(),
        }
    )
    return ok(
        {
            "ok": True,
            "expires_at": expires_at,
            "plan_days": row.get("plan_days"),
            "token": token,
            "server_time": now_iso(),
            "message": "فعال‌سازی موفق",
        }
    )


@app.route("/validate", methods=["POST", "OPTIONS"])
def validate():
    if request.method == "OPTIONS":
        return ok({"ok": True})
    if not LICENSE_SECRET:
        return ok({"ok": False, "error": "LICENSE_SECRET تنظیم نشده"}, 500)

    body = request.get_json(silent=True) or {}
    code = str(body.get("code") or "").strip()
    machine_id = str(body.get("machine_id") or "").strip()
    if not code or not machine_id:
        return ok({"ok": False, "error": "کد و شناسه دستگاه الزامی است"}, 400)

    key = normalize_code(code)
    db = load_db()
    row = db.get(key)
    if not row:
        return ok({"ok": False, "error": "لایسنس پیدا نشد"}, 404)
    if row.get("status") == "revoked":
        return ok({"ok": False, "error": "این کد باطل شده است"}, 403)
    if not row.get("machine_id") or row["machine_id"] != machine_id:
        return ok({"ok": False, "error": "این لایسنس برای این سیستم نیست"}, 403)
    if row.get("expires_at") and row["expires_at"] < now_iso():
        row["status"] = "expired"
        db[key] = row
        save_db(db)
        return ok({"ok": False, "error": "اعتبار لایسنس تمام شده است"}, 403)

    row["last_validate_at"] = now_iso()
    db[key] = row
    save_db(db)
    token = make_token(
        {
            "code": row["code"],
            "machine_id": machine_id,
            "expires_at": row["expires_at"],
            "activated_at": row.get("activated_at"),
            "plan_days": row.get("plan_days"),
            "iat": now_iso(),
        }
    )
    return ok(
        {
            "ok": True,
            "expires_at": row["expires_at"],
            "plan_days": row.get("plan_days"),
            "token": token,
            "server_time": now_iso(),
        }
    )


@app.route("/admin/create", methods=["POST", "OPTIONS"])
def admin_create():
    if request.method == "OPTIONS":
        return ok({"ok": True})
    if not require_admin():
        return ok({"ok": False, "error": "دسترسی غیرمجاز"}, 401)

    body = request.get_json(silent=True) or {}
    plan_days = int(body.get("plan_days") or 30)
    note = str(body.get("note") or "")[:200]
    count = min(max(int(body.get("count") or 1), 1), 50)
    if plan_days <= 0 or plan_days > 20000:
        return ok({"ok": False, "error": "plan_days نامعتبر است"}, 400)

    db = load_db()
    created = []
    for _ in range(count):
        code = generate_code()
        key = normalize_code(code)
        for _try in range(5):
            if key not in db:
                break
            code = generate_code()
            key = normalize_code(code)
        db[key] = {
            "code": code,
            "plan_days": plan_days,
            "status": "unused",
            "created_at": now_iso(),
            "activated_at": None,
            "expires_at": None,
            "machine_id": None,
            "machine_id_history": [],
            "transfer_count": 0,
            "max_transfers": 2,
            "last_validate_at": None,
            "note": note,
        }
        created.append(code)
    save_db(db)
    return ok({"ok": True, "plan_days": plan_days, "count": len(created), "codes": created})


@app.route("/admin/revoke", methods=["POST", "OPTIONS"])
def admin_revoke():
    if request.method == "OPTIONS":
        return ok({"ok": True})
    if not require_admin():
        return ok({"ok": False, "error": "دسترسی غیرمجاز"}, 401)

    body = request.get_json(silent=True) or {}
    code = str(body.get("code") or "").strip()
    if not code:
        return ok({"ok": False, "error": "code الزامی است"}, 400)

    key = normalize_code(code)
    db = load_db()
    row = db.get(key)
    if not row:
        return ok({"ok": False, "error": "کد پیدا نشد"}, 404)

    row["status"] = "revoked"
    row["machine_id"] = None
    row["last_validate_at"] = now_iso()
    db[key] = row
    save_db(db)
    return ok({"ok": True, "message": "کد باطل شد", "code": row.get("code")})


@app.route("/admin/extend", methods=["POST", "OPTIONS"])
def admin_extend():
    if request.method == "OPTIONS":
        return ok({"ok": True})
    if not require_admin():
        return ok({"ok": False, "error": "دسترسی غیرمجاز"}, 401)

    body = request.get_json(silent=True) or {}
    code = str(body.get("code") or "").strip()
    extra_days = int(body.get("extra_days") or 0)
    if not code or extra_days <= 0:
        return ok({"ok": False, "error": "code و extra_days الزامی است"}, 400)

    key = normalize_code(code)
    db = load_db()
    row = db.get(key)
    if not row:
        return ok({"ok": False, "error": "کد پیدا نشد"}, 404)

    base = row.get("expires_at") or now_iso()
    try:
        base_dt = datetime.fromisoformat(base.replace("Z", "+00:00"))
    except Exception:
        base_dt = datetime.now(timezone.utc)
    if base_dt.tzinfo is None:
        base_dt = base_dt.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if base_dt < now:
        base_dt = now

    new_exp = (base_dt + timedelta(days=extra_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    row["expires_at"] = new_exp
    if row.get("machine_id"):
        row["status"] = "active"
    db[key] = row
    save_db(db)
    return ok({"ok": True, "code": row.get("code"), "expires_at": new_exp})


@app.route("/admin/list", methods=["GET", "OPTIONS"])
def admin_list():
    if request.method == "OPTIONS":
        return ok({"ok": True})
    if not require_admin():
        return ok({"ok": False, "error": "دسترسی غیرمجاز"}, 401)

    db = load_db()
    items = list(db.values())
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return ok({"ok": True, "count": len(items), "licenses": items})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
