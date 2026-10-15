
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, secrets, mimetypes
from datetime import datetime
from functools import wraps

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# On hosts with a persistent disk, set DAILYUPDATES_DATA_DIR to its mount path
# (Render example: /var/data). Locally, data stays inside the project folder.
DATA_DIR = os.path.abspath(os.environ.get("DAILYUPDATES_DATA_DIR", BASE_DIR))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "dailyupdates.db")
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
USER_FILES_ROOT = os.path.join(DATA_DIR, "user_files")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "pdf", "txt", "doc", "docx", "xlsx"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(USER_FILES_ROOT, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("DAILYUPDATES_SECRET") or os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB per request

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            audience TEXT NOT NULL DEFAULT 'All Users',
            attachment TEXT,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS update_reads (
            user_id INTEGER NOT NULL,
            update_id INTEGER NOT NULL,
            read_at TEXT NOT NULL,
            PRIMARY KEY(user_id, update_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(update_id) REFERENCES updates(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS user_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            file_category TEXT NOT NULL,
            is_shared INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        admin = con.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not admin:
            con.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                ("admin", generate_password_hash("Admin@123"), "admin", datetime.now().isoformat(timespec="seconds"))
            )

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
