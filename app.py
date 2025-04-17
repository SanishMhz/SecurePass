from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import sqlite3
import os
from datetime import timedelta
import logging

# Enable debug logging for Flask-Dance
logging.basicConfig(level=logging.DEBUG)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or "dev_secret"
app.permanent_session_lifetime = timedelta(minutes=30)

# Allow insecure OAuth for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# --- OAuth Setup ---
# GitHub OAuth
github_bp = make_github_blueprint(
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    redirect_url="http://127.0.0.1:5000/login/github/authorized"
)
app.register_blueprint(github_bp, url_prefix="/login")

# Google OAuth
google_bp = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    scope=[
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid"
    ],
    redirect_url="/google/callback"
)
app.register_blueprint(google_bp, url_prefix="/login")

# --- Database Initialization ---
def init_db():
    with sqlite3.connect("db.sqlite3") as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT UNIQUE,
                is_oauth INTEGER DEFAULT 0
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                site TEXT NOT NULL,
                site_username TEXT NOT NULL,
                site_password TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        # Create default admin user
        c.execute("SELECT * FROM users WHERE username = ?", ("admin",))
        if not c.fetchone():
            admin_pass = generate_password_hash("admin123")
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", admin_pass))
        conn.commit()

init_db()

# --- Routes ---
@app.route("/")
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("landing.html")

@app.route("/test")
def test():
    return render_template("test.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with sqlite3.connect("db.sqlite3") as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user and check_password_hash(user[1], password):
                session.permanent = True
                session['user_id'] = user[0]
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/login/google")
def google_login():
    return redirect(url_for("google.login"))

@app.route("/google/callback")
def google_callback():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Failed to fetch user info from Google", 400

    user_info = resp.json()
    email = user_info.get("email")

    if not email:
        return "Failed to get email from Google", 400

    # Check or create user in DB
    with sqlite3.connect("db.sqlite3") as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        if not user:
            c.execute("INSERT INTO users (email, is_oauth) VALUES (?, 1)", (email,))
            conn.commit()
            user_id = c.lastrowid
        else:
            user_id = user[0]

    session.permanent = True
    session["user_id"] = user_id
    session["username"] = email
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("db.sqlite3") as conn:
        c = conn.cursor()
        c.execute("SELECT id, site, site_username, site_password FROM passwords WHERE user_id = ?", (session['user_id'],))
        passwords = c.fetchall()

    return render_template("dashboard.html", passwords=passwords)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
