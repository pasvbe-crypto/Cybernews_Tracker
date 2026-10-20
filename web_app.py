from contextlib import contextmanager
from datetime import datetime
from functools import wraps
import hashlib
import json
import os
import secrets
import sqlite3
import time

import click
from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["DATABASE"] = os.path.join(app.instance_path, "cybernews.sqlite3")
app.config["SESSION_COOKIE_NAME"] = "session_token"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", ""
).lower() in {"1", "true", "yes"}

AVAILABLE_ROLES = ("User", "Teaching Assistant", "GOAT")


class ServerSideSession(CallbackDict, SessionMixin):
  def __init__(self, initial=None, sid=None, new=False):
    self.sid = sid
    self.new = new
    self.modified = False
    super().__init__(initial, lambda _session: setattr(self, "modified", True))


class SQLiteSessionInterface(SessionInterface):
  session_class = ServerSideSession

  def open_session(self, app, request):
    sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
    if not sid:
      return self.session_class()

    sid_hash = hashlib.sha256(sid.encode("utf-8")).hexdigest()
    with get_db_connection() as connection:
      stored_session = connection.execute(
          "SELECT data, expires_at FROM sessions WHERE sid_hash = ?",
          (sid_hash,),
      ).fetchone()

    if stored_session is None or stored_session["expires_at"] <= time.time():
      with get_db_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash,))
      invalid_session = self.session_class(sid=sid)
      invalid_session.modified = True
      return invalid_session

    try:
      data = json.loads(stored_session["data"])
    except (TypeError, json.JSONDecodeError):
      with get_db_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash,))
      invalid_session = self.session_class(sid=sid)
      invalid_session.modified = True
      return invalid_session

    return self.session_class(data, sid=sid)

  def save_session(self, app, session, response):
    cookie_name = app.config["SESSION_COOKIE_NAME"]
    if not session:
      if session.modified and session.sid:
        sid_hash = hashlib.sha256(session.sid.encode("utf-8")).hexdigest()
        with get_db_connection() as connection:
          connection.execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash,))
        response.delete_cookie(
            cookie_name,
            path=app.config["SESSION_COOKIE_PATH"],
            domain=app.config["SESSION_COOKIE_DOMAIN"],
        )
      return

    if not session.modified and not session.new:
      return

    sid = session.sid or secrets.token_urlsafe(32)
    sid_hash = hashlib.sha256(sid.encode("utf-8")).hexdigest()
    lifetime = app.permanent_session_lifetime
    expires_at = time.time() + lifetime.total_seconds()
    with get_db_connection() as connection:
      connection.execute(
          """
          INSERT INTO sessions (sid_hash, data, expires_at)
          VALUES (?, ?, ?)
          ON CONFLICT(sid_hash) DO UPDATE SET
            data = excluded.data,
            expires_at = excluded.expires_at
          """,
          (sid_hash, json.dumps(dict(session)), expires_at),
      )

    response.set_cookie(
        cookie_name,
        sid,
        max_age=int(lifetime.total_seconds()),
        httponly=app.config["SESSION_COOKIE_HTTPONLY"],
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite=app.config["SESSION_COOKIE_SAMESITE"],
        path=app.config["SESSION_COOKIE_PATH"],
        domain=app.config["SESSION_COOKIE_DOMAIN"],
    )
    session.sid = sid
    session.modified = False


app.session_interface = SQLiteSessionInterface()


@contextmanager
def get_db_connection():
  connection = sqlite3.connect(app.config["DATABASE"])
  connection.row_factory = sqlite3.Row
  try:
    connection.execute("PRAGMA foreign_keys = ON")
    yield connection
    connection.commit()
  except Exception:
    connection.rollback()
    raise
  finally:
    connection.close()


def initialize_database():
  os.makedirs(app.instance_path, exist_ok=True)
  with get_db_connection() as connection:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'Viewer'
        )
        """
    )
    user_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(users)")
    }
    if "created_at" not in user_columns:
      connection.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
    if "last_login_at" not in user_columns:
      connection.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
          sid_hash TEXT PRIMARY KEY,
          data TEXT NOT NULL,
          expires_at REAL NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS discussions (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY,
          discussion_id INTEGER NOT NULL
            REFERENCES discussions(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_discussions_created "
        "ON discussions(created_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_comments_discussion_created "
        "ON comments(discussion_id, created_at)"
    )


initialize_database()


@app.cli.command("create-user")
@click.argument("username")
def create_user(username):
  """Create a user account with a securely hashed password."""
  password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
  try:
    with get_db_connection() as connection:
      connection.execute(
          "INSERT INTO users (username, password_hash, role, created_at) "
          "VALUES (?, ?, 'User', ?)",
          (
              username,
              generate_password_hash(password),
              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
          ),
      )
  except sqlite3.IntegrityError as error:
    raise click.ClickException("That username already exists.") from error
  click.echo(f"User '{username}' created.")


@app.route("/")
def home():
  return render_template("home.html")


@app.before_request
def load_logged_in_user():
  user_id = session.get("user_id")
  g.current_user = None
  if user_id is None:
    return

  with get_db_connection() as connection:
    user = connection.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

  if user is None:
    session.clear()
    return

  with get_db_connection() as connection:
    account_details = connection.execute(
        "SELECT created_at, last_login_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

  if session.get("role") != user["role"]:
    session["role"] = user["role"]

  g.current_user = {
      "id": user["id"],
      "username": user["username"],
      "role": user["role"],
      "login_time": session.get("login_time"),
      "created_at": account_details["created_at"],
      "last_login_at": account_details["last_login_at"],
  }


@app.context_processor
def inject_current_user():
  return {
      "current_user": g.get("current_user"),
      "csrf_token": generate_csrf_token,
  }


def generate_csrf_token():
  token = session.get("_csrf_token")
  if token is None:
    token = secrets.token_urlsafe(32)
    session["_csrf_token"] = token
  return token


def validate_csrf_token():
  expected = session.get("_csrf_token", "")
  submitted = request.form.get("csrf_token", "")
  if not expected or not secrets.compare_digest(expected, submitted):
    abort(400, description="Invalid or missing CSRF token.")


def login_required(view):
  @wraps(view)
  def wrapped_view(*args, **kwargs):
    if g.current_user is None:
      return redirect(url_for("cookie_check"))
    return view(*args, **kwargs)

  return wrapped_view


def admin_required(view):
  @wraps(view)
  def wrapped_view(*args, **kwargs):
    if g.current_user is None:
      return redirect(url_for("cookie_check"))
    role = g.current_user["role"].strip().casefold()
    if (
        g.current_user["username"].casefold() != "patrick"
        or role not in {"admin", "administrator"}
    ):
      abort(403)
    return view(*args, **kwargs)

  return wrapped_view


def account_required(username, roles):
  allowed_roles = {role.casefold() for role in roles}

  def decorator(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
      if g.current_user is None:
        return redirect(url_for("cookie_check"))
      if (
          g.current_user["username"].casefold() != username.casefold()
          or g.current_user["role"].casefold() not in allowed_roles
      ):
        abort(403)
      return view(*args, **kwargs)

    return wrapped_view

  return decorator


@app.route("/news")
def news():
  username = g.current_user["username"] if g.current_user else "Guest"
  articles = [
      {
          "title": "New AI Breakthrough",
          "summary": (
              "Researchers develop secure language models to prevent prompt"
              " injection."
          ),
      },
      {
          "title": "Cyberattack on Major Bank",
          "summary": (
              "Millions of account details compromised in a sophisticated"
              " breach."
          ),
      },
      {
          "title": "Flask 3.0 Released",
          "summary": (
              "The new version simplifies routing and enhances async support."
          ),
      },
  ]
  last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")

  return render_template(
      "news.html",
      username=username,
      articles=articles,
      last_updated=last_updated,
  )


@app.route("/forum")
@login_required
def forum():
  with get_db_connection() as connection:
    discussions = connection.execute(
        """
        SELECT d.id, d.title, d.body, d.created_at, u.username,
               COUNT(c.id) AS comment_count
        FROM discussions AS d
        JOIN users AS u ON u.id = d.user_id
        LEFT JOIN comments AS c ON c.discussion_id = d.id
        GROUP BY d.id
        ORDER BY d.created_at DESC, d.id DESC
        LIMIT 100
        """
    ).fetchall()
  return render_template("forum.html", discussions=discussions)


@app.route("/forum/new", methods=["GET", "POST"])
@login_required
def new_discussion():
  error = None
  title = ""
  body = ""
  if request.method == "POST":
    validate_csrf_token()
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title:
      error = "Please enter a discussion title."
    elif len(title) > 160:
      error = "Discussion titles must be 160 characters or fewer."
    elif not body:
      error = "Please enter a discussion message."
    elif len(body) > 10000:
      error = "Discussion messages must be 10,000 characters or fewer."
    else:
      with get_db_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO discussions (user_id, title, body, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                g.current_user["id"],
                title,
                body,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        discussion_id = cursor.lastrowid
      return redirect(url_for("view_discussion", discussion_id=discussion_id))

  return render_template(
      "forum_new.html",
      error=error,
      title=title,
      body=body,
  ), 400 if error else 200


@app.route("/forum/<int:discussion_id>", methods=["GET", "POST"])
@login_required
def view_discussion(discussion_id):
  error = None
  comment_body = ""
  if request.method == "POST":
    validate_csrf_token()
    comment_body = request.form.get("body", "").strip()
    if not comment_body:
      error = "Please enter a comment."
    elif len(comment_body) > 5000:
      error = "Comments must be 5,000 characters or fewer."
    else:
      with get_db_connection() as connection:
        exists = connection.execute(
            "SELECT 1 FROM discussions WHERE id = ?",
            (discussion_id,),
        ).fetchone()
        if exists is None:
          abort(404)
        connection.execute(
            "INSERT INTO comments "
            "(discussion_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
            (
                discussion_id,
                g.current_user["id"],
                comment_body,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
      return redirect(url_for("view_discussion", discussion_id=discussion_id))

  with get_db_connection() as connection:
    discussion = connection.execute(
        """
        SELECT d.id, d.title, d.body, d.created_at, u.username
        FROM discussions AS d
        JOIN users AS u ON u.id = d.user_id
        WHERE d.id = ?
        """,
        (discussion_id,),
    ).fetchone()
    if discussion is None:
      abort(404)
    comments = connection.execute(
        """
        SELECT c.body, c.created_at, u.username
        FROM comments AS c
        JOIN users AS u ON u.id = c.user_id
        WHERE c.discussion_id = ?
        ORDER BY c.created_at, c.id
        """,
        (discussion_id,),
    ).fetchall()

  return render_template(
      "forum_discussion.html",
      discussion=discussion,
      comments=comments,
      error=error,
      comment_body=comment_body,
  ), 400 if error else 200


@app.route("/free-money")
def free_money():
  role = g.current_user["role"] if g.current_user else None
  return render_template("free_money.html", role=role)


@app.route("/demo-donation")
@account_required("Alen", {"Teaching Assistant"})
def demo_donation():
  return render_template("demo_donation.html")


@app.route("/demo-withdrawal")
@account_required("Patrick", {"Administrator", "Admin"})
def demo_withdrawal():
  return render_template("demo_withdrawal.html")


@app.route("/dashboard")
@login_required
def user_dashboard():
  if (
      g.current_user["username"].casefold() == "patrick"
      and g.current_user["role"].strip().casefold()
      in {"admin", "administrator"}
  ):
    return redirect(url_for("admin_dashboard"))
  return render_template("user_dashboard.html", user=g.current_user)


@app.route("/admin")
@admin_required
def admin_dashboard():
  with get_db_connection() as connection:
    users = connection.execute(
        "SELECT id, username, role, created_at, last_login_at "
        "FROM users ORDER BY username"
    ).fetchall()
  return render_template(
      "admin_dashboard.html",
      user=g.current_user,
      users=users,
      available_roles=AVAILABLE_ROLES,
  )


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_user_role(user_id):
  validate_csrf_token()
  role = request.form.get("role", "")
  if role not in AVAILABLE_ROLES:
    abort(400, description="Invalid user role.")

  with get_db_connection() as connection:
    target = connection.execute(
        "SELECT username FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if target is None:
      abort(404)
    if target["username"].casefold() == "patrick":
      abort(400, description="Patrick's administrator account cannot be changed here.")
    connection.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (role, user_id),
    )

  return redirect(url_for("admin_dashboard"))


@app.route("/cookie-check")
def cookie_check():
  return render_template(
      "cookie_check.html",
      user=g.current_user,
      registered=request.args.get("registered") == "1",
  )


@app.route("/register", methods=["GET", "POST"])
def register():
  if g.current_user is not None:
    return redirect(url_for("user_dashboard"))

  error = None
  username = ""
  if request.method == "POST":
    validate_csrf_token()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username:
      error = "Please enter a username."
    elif len(username) > 80:
      error = "Username must be 80 characters or fewer."
    elif len(password) < 8:
      error = "Password must be at least 8 characters."
    else:
      try:
        with get_db_connection() as connection:
          connection.execute(
              "INSERT INTO users (username, password_hash, role, created_at) "
              "VALUES (?, ?, 'User', ?)",
              (
                  username,
                  generate_password_hash(password),
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              ),
          )
      except sqlite3.IntegrityError:
        error = "That username is already taken."
      else:
        return redirect(url_for("cookie_check", registered="1"))

  return render_template(
      "register.html",
      error=error,
      username=username,
  ), 400 if error else 200


@app.route("/login", methods=["GET", "POST"])
def login():
  if request.method == "POST":
    validate_csrf_token()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    with get_db_connection() as connection:
      user = connection.execute(
          "SELECT id, username, password_hash, role FROM users "
          "WHERE username = ?",
          (username,),
      ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
      return render_template(
          "cookie_check.html",
          user=g.current_user,
          error="Invalid username or password.",
      ), 401

    previous_sid = session.sid
    session.clear()
    if previous_sid:
      previous_sid_hash = hashlib.sha256(
          previous_sid.encode("utf-8")
      ).hexdigest()
      with get_db_connection() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE sid_hash = ?",
            (previous_sid_hash,),
        )
    session.sid = None
    session.new = True
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    session.permanent = True
    with get_db_connection() as connection:
      connection.execute(
          "UPDATE users SET last_login_at = ? WHERE id = ?",
          (session["login_time"], user["id"]),
      )
    if (
        user["username"].casefold() == "patrick"
        and user["role"].strip().casefold() in {"admin", "administrator"}
    ):
      return redirect(url_for("admin_dashboard"))
    return redirect(url_for("user_dashboard"))

  return render_template("cookie_check.html", user=g.current_user)


@app.route("/logout", methods=["POST"])
def logout():
  if g.current_user is None:
    return redirect(url_for("home"))

  validate_csrf_token()
  previous_sid = session.sid
  session.clear()
  if previous_sid:
    previous_sid_hash = hashlib.sha256(
        previous_sid.encode("utf-8")
    ).hexdigest()
    with get_db_connection() as connection:
      connection.execute(
          "DELETE FROM sessions WHERE sid_hash = ?",
          (previous_sid_hash,),
      )
  session.sid = None
  session.new = True
  session["logout_success"] = True
  return redirect(url_for("logout_success"))


@app.route("/logout-success")
def logout_success():
  if not session.pop("logout_success", False):
    return redirect(url_for("home"))
  return render_template("logout_success.html")


# 1. GET-Route für das Kontaktformular
@app.route("/contact", methods=["GET"])
def contact():
  return render_template("contact_form.html")


@app.route("/impressum")
def impressum():
  return render_template("impressum.html")


# 2. POST-Route für die Verarbeitung der Formulardaten
@app.route("/submit-message", methods=["POST"])
def submit_message():
  validate_csrf_token()
  name = request.form.get("name")
  email = request.form.get("email")
  message = request.form.get("message")

  # Hier verarbeiten/speichern wir die Daten später bei Bedarf
  return render_template("confirmation.html", name=name)


if __name__ == "__main__":
  app.run(debug=True)