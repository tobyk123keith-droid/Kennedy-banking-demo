from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, secrets, re

APP_SECRET = os.environ.get("APP_SECRET", secrets.token_hex(16))
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "bank.db"))
CSRF_KEY = "_csrf_token"

app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))
    db.commit()

def create_account_for_user(user_id):
    db = get_db()
    acct_num = "22" + secrets.token_hex(5).upper()
    db.execute("INSERT INTO accounts (user_id, account_number, balance_cents) VALUES (?, ?, ?)", 
               (user_id, acct_num, 100_00))
    db.commit()

def gen_csrf_token():
    token = secrets.token_urlsafe(16)
    session[CSRF_KEY] = token
    return token

def validate_csrf():
    token_form = request.form.get(CSRF_KEY, "")
    token_session = session.get(CSRF_KEY, None)
    if not token_session or token_form != token_session:
        return False
    session.pop(CSRF_KEY, None)
    return True

@app.context_processor
def inject_csrf():
    return {"csrf_token": gen_csrf_token, "CSRF_KEY": CSRF_KEY}

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def home():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid CSRF token.", "danger")
            return redirect(url_for("register"))
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
            flash("Username must be 3â20 chars: lowercase letters, digits, underscore.", "danger")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                       (username, generate_password_hash(password)))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))
        user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        create_account_for_user(user["id"])
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid CSRF token.", "danger")
            return redirect(url_for("login"))
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
        session["user_id"] = user["id"]
        flash("Welcome back!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = current_user()
    acct = db.execute("SELECT * FROM accounts WHERE user_id=?", (user["id"],)).fetchone()
    txns = db.execute(\"\"\"
        SELECT t.*, 
               fa.account_number as from_acct, 
               ta.account_number as to_acct
        FROM transactions t
        LEFT JOIN accounts fa ON fa.id = t.from_account_id
        LEFT JOIN accounts ta ON ta.id = t.to_account_id
        WHERE t.from_account_id = ? OR t.to_account_id = ?
        ORDER BY t.id DESC LIMIT 10
    \"\"\", (acct["id"], acct["id"])).fetchall()
    return render_template("dashboard.html", acct=acct, txns=txns)

@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    if not validate_csrf():
        flash("Invalid CSRF token.", "danger")
        return redirect(url_for("dashboard"))
    amount_str = request.form.get("amount","").strip()
    note = request.form.get("note","").strip()[:140]
    to_username = request.form.get("to_username","").strip().lower()

    try:
        import re
        if not re.fullmatch(r"\\d+(\\.\\d{1,2})?", amount_str):
            raise ValueError("Invalid amount format")
        naira = float(amount_str)
        if naira <= 0:
            raise ValueError("Amount must be positive")
        amount_cents = int(round(naira * 100))
    except Exception:
        flash("Invalid amount.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    user = current_user()
    from_acct = db.execute("SELECT * FROM accounts WHERE user_id=?", (user["id"],)).fetchone()
    to_user = db.execute("SELECT * FROM users WHERE username=?", (to_username,)).fetchone()
    if not to_user:
        flash("Recipient not found.", "danger")
        return redirect(url_for("dashboard"))
    to_acct = db.execute("SELECT * FROM accounts WHERE user_id=?", (to_user["id"],)).fetchone()
    if from_acct["id"] == to_acct["id"]:
        flash("Cannot transfer to your own account.", "warning")
        return redirect(url_for("dashboard"))
    if from_acct["balance_cents"] < amount_cents:
        flash("Insufficient balance.", "danger")
        return redirect(url_for("dashboard"))

    try:
        db.execute("BEGIN")
        db.execute("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id=?", (amount_cents, from_acct["id"]))
        db.execute("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id=?", (amount_cents, to_acct["id"]))
        db.execute("INSERT INTO transactions (from_account_id, to_account_id, amount_cents, note) VALUES (?, ?, ?, ?)", 
                   (from_acct["id"], to_acct["id"], amount_cents, note))
        db.commit()
        flash("Transfer successful!", "success")
    except Exception:
        db.rollback()
        flash("Transfer failed. Try again.", "danger")
    return redirect(url_for("dashboard"))

@app.cli.command("init-db")
def cli_init_db():
    init_db()
    print("Database initialized.")

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        with app.app_context():
            init_db()
    app.run(debug=True)
