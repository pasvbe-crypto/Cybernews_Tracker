from contextlib import contextmanager
from datetime import datetime
from functools import wraps
import hashlib
from http.client import HTTPException
import json
import os
import secrets
import sqlite3
import time
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

import click
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["DATABASE"] = os.environ.get("DATABASE_PATH") or os.path.join(
    app.instance_path, "cybernews.sqlite3"
)
app.config["SESSION_COOKIE_NAME"] = "session_token"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", ""
).lower() in {"1", "true", "yes"}

AVAILABLE_ROLES = ("User", "Teaching Assistant", "GOAT")
CP_SHOP_ITEMS = (
    {
        "code": "cup",
        "name": "Cup",
        "points": 500,
        "image": "shop/cup.jpg",
    },
    {
        "code": "beanie",
        "name": "Beanie",
        "points": 800,
        "image": "shop/beanie.jpg",
    },
    {
        "code": "t-shirt",
        "name": "T-Shirt",
        "points": 1200,
        "image": "shop/t-shirt.jpg",
    },
    {
        "code": "hoodie",
        "name": "Hoodie",
        "points": 2000,
        "image": "shop/hoodie.jpg",
    },
    {
        "code": "headphones",
        "name": "Headphones",
        "points": 2500,
        "image": "shop/headphones.jpg",
    },
    {
        "code": "tesla-rocket",
        "name": "Tesla Rocket",
        "points": 100000,
        "image": "shop/tesla-rocket.jpg",
    },
)
HACK_ME_LEVELS = (
    {
        "number": 1,
        "title": "Inventory the lab",
        "mission": "List the files in the simulated lab folder to locate its briefing.",
        "hint": "Use the PowerShell command that lists items in the current directory.",
        "commands": ("get-childitem", "gci", "dir", "ls"),
        "output": (
            "Directory: C:\\Lab\n\n"
            "Mode    Name\n"
            "----    ----\n"
            "-a---    briefing.txt\n"
            "-a---    auth.log\n"
            "-a---    evidence.zip"
        ),
        "points": 1,
    },
    {
        "number": 2,
        "title": "Read the briefing",
        "mission": "Read briefing.txt to learn which simulated log needs investigating.",
        "hint": "Use Get-Content with the briefing file path.",
        "commands": (
            "get-content .\\briefing.txt",
            "gc .\\briefing.txt",
            "cat .\\briefing.txt",
            "type .\\briefing.txt",
        ),
        "output": (
            "Investigation note:\n"
            "Search auth.log for failed sign-in events before reviewing the evidence."
        ),
        "points": 3,
    },
    {
        "number": 3,
        "title": "Search the sign-in log",
        "mission": "Find failed sign-in events in the simulated auth.log.",
        "hint": "Use Select-String with the log path and the pattern failed.",
        "commands": (
            'select-string -path .\\auth.log -pattern "failed"',
            "select-string -path .\\auth.log -pattern failed",
            "sls -path .\\auth.log -pattern failed",
        ),
        "output": (
            "auth.log:12: 08:42:10 user=alex event=failed-sign-in\n"
            "auth.log:18: 08:44:03 user=alex event=failed-sign-in\n"
            "Summary: 2 failed sign-ins found for alex (simulated records)."
        ),
        "points": 5,
    },
    {
        "number": 4,
        "title": "Review the process list",
        "mission": "Sort the simulated process list by CPU usage, highest first.",
        "hint": "Pipe Get-Process into Sort-Object using the CPU property and descending order.",
        "commands": (
            "get-process | sort-object cpu -descending",
            "get-process | sort-object cpu -desc",
            "gps | sort-object cpu -descending",
            "gps | sort-object cpu -desc",
        ),
        "output": (
            "Name             CPU (simulated)\n"
            "----             ---------------\n"
            "backup-agent      12.4\n"
            "audit-viewer       3.1\n"
            "notepad            0.4"
        ),
        "points": 10,
    },
    {
        "number": 5,
        "title": "Fingerprint the evidence",
        "mission": "Calculate a SHA256 hash for the simulated evidence.zip file.",
        "hint": "Use Get-FileHash with the file path and SHA256 algorithm.",
        "commands": (
            "get-filehash .\\evidence.zip -algorithm sha256",
            "get-filehash .\\evidence.zip -algorithm sha-256",
        ),
        "output": (
            "Algorithm  Hash\n"
            "---------  ----\n"
            "SHA256     7F3A91D45C6B2E08A1F04D77236B9C50"
            "8A6E2D1F4C7B9053E6A21D8F0B4C7291\n"
            "Simulated fingerprint recorded."
        ),
        "points": 25,
    },
)


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
  database_directory = os.path.dirname(os.path.abspath(app.config["DATABASE"]))
  os.makedirs(database_directory, exist_ok=True)
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
    if "cyberhacks_points" not in user_columns:
      connection.execute(
          "ALTER TABLE users ADD COLUMN cyberhacks_points "
          "INTEGER NOT NULL DEFAULT 0"
      )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS app_migrations (
          name TEXT PRIMARY KEY,
          applied_at TEXT NOT NULL
        )
        """
    )
    patrick_points_migration = "set-patrick-cyberhacks-points-to-100000"
    migration_applied = connection.execute(
        "SELECT 1 FROM app_migrations WHERE name = ?",
        (patrick_points_migration,),
    ).fetchone()
    if migration_applied is None:
      patrick = connection.execute(
          "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
          ("Patrick",),
      ).fetchone()
      if patrick is not None:
        connection.execute(
            "UPDATE users SET cyberhacks_points = 100000 WHERE id = ?",
            (patrick["id"],),
        )
        connection.execute(
            "INSERT INTO app_migrations (name, applied_at) VALUES (?, ?)",
            (
                patrick_points_migration,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
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
        CREATE TABLE IF NOT EXISTS cyberhacks_awards (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          run_id TEXT NOT NULL,
          level INTEGER NOT NULL CHECK (level BETWEEN 1 AND 5),
          points INTEGER NOT NULL CHECK (points > 0),
          earned_at TEXT NOT NULL,
          UNIQUE(user_id, run_id, level)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS cp_shop_orders (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          item_code TEXT NOT NULL,
          item_name TEXT NOT NULL,
          points_spent INTEGER NOT NULL CHECK (points_spent > 0),
          recipient_name TEXT NOT NULL,
          shipping_address TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'fulfilled')),
          created_at TEXT NOT NULL,
          fulfilled_at TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_cp_shop_orders_status_created "
        "ON cp_shop_orders(status, created_at DESC)"
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
        """
        SELECT id, username, role, created_at, last_login_at,
               cyberhacks_points
        FROM users WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

  if user is None:
    session.clear()
    return

  if session.get("role") != user["role"]:
    session["role"] = user["role"]

  g.current_user = {
      "id": user["id"],
      "username": user["username"],
      "role": user["role"],
      "login_time": session.get("login_time"),
      "created_at": user["created_at"],
      "last_login_at": user["last_login_at"],
      "cyberhacks_points": user["cyberhacks_points"],
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
  last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")

  return render_template(
      "news.html",
      username=username,
      last_updated=last_updated,
  )


@app.route("/hack-me", methods=["GET", "POST"])
@login_required
def hack_me():
  if request.method == "POST":
    validate_csrf_token()
    action = request.form.get("action", "command")
    if action == "replay":
      session["hack_me_run_id"] = secrets.token_urlsafe(24)
      session["hack_me_level"] = 1
      session["hack_me_earned"] = 0
      session.pop("hack_me_last_command", None)
      session.pop("hack_me_last_output", None)
      session["hack_me_notice"] = "New playthrough started. Earn CP again!"
      return redirect(url_for("hack_me"))
    if action != "command":
      abort(400, description="Invalid Hack Me action.")

    level_number = session.get("hack_me_level", 1)
    if (
        not isinstance(level_number, int)
        or isinstance(level_number, bool)
        or not 1 <= level_number <= len(HACK_ME_LEVELS) + 1
    ):
      session["hack_me_run_id"] = secrets.token_urlsafe(24)
      session["hack_me_level"] = 1
      session["hack_me_earned"] = 0
      session["hack_me_notice"] = "Invalid game progress was reset to Level 1."
      return redirect(url_for("hack_me"))
    if level_number == len(HACK_ME_LEVELS) + 1:
      session["hack_me_notice"] = "You completed all five levels. Replay to earn again."
      return redirect(url_for("hack_me"))

    level = HACK_ME_LEVELS[level_number - 1]
    raw_command = request.form.get("command", "")
    if len(raw_command) > 200:
      session["hack_me_last_command"] = ""
      session["hack_me_last_output"] = "Commands must be 200 characters or fewer."
      session["hack_me_notice"] = "Commands must be 200 characters or fewer."
      return redirect(url_for("hack_me"))

    command = " ".join(raw_command.strip().split()).casefold()
    if command not in level["commands"]:
      session["hack_me_last_command"] = raw_command
      session["hack_me_last_output"] = (
          "Command not recognized by the simulated lab. "
          "Use the level hint and try again."
      )
      session["hack_me_notice"] = (
          f"That command did not solve Level {level_number}. "
          "This terminal only accepts safe, simulated game commands."
      )
      return redirect(url_for("hack_me"))

    run_id = session.get("hack_me_run_id")
    if not isinstance(run_id, str):
      run_id = secrets.token_urlsafe(24)
      session["hack_me_run_id"] = run_id
      session["hack_me_level"] = 1
      session["hack_me_earned"] = 0
      return redirect(url_for("hack_me"))

    award_recorded = False
    with get_db_connection() as connection:
      cursor = connection.execute(
          """
          INSERT INTO cyberhacks_awards
              (user_id, run_id, level, points, earned_at)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(user_id, run_id, level) DO NOTHING
          """,
          (
              g.current_user["id"],
              run_id,
              level_number,
              level["points"],
              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
          ),
      )
      award_recorded = cursor.rowcount == 1
      if award_recorded:
        connection.execute(
            "UPDATE users SET cyberhacks_points = "
            "cyberhacks_points + ? WHERE id = ?",
            (level["points"], g.current_user["id"]),
        )

    session["hack_me_level"] = level_number + 1
    session["hack_me_last_command"] = raw_command
    session["hack_me_last_output"] = level["output"]
    if award_recorded:
      session["hack_me_earned"] = (
          session.get("hack_me_earned", 0) + level["points"]
      )
      session["hack_me_notice"] = (
          f"Level {level_number} complete! +{level['points']} CP"
      )
    else:
      session["hack_me_notice"] = (
          f"Level {level_number} was already rewarded in this playthrough."
      )
    return redirect(url_for("hack_me"))

  level_number = session.get("hack_me_level", 1)
  if (
      not isinstance(level_number, int)
      or isinstance(level_number, bool)
      or not 1 <= level_number <= len(HACK_ME_LEVELS) + 1
  ):
    session["hack_me_run_id"] = secrets.token_urlsafe(24)
    session["hack_me_level"] = 1
    session["hack_me_earned"] = 0
    session.pop("hack_me_last_command", None)
    session.pop("hack_me_last_output", None)
    session["hack_me_notice"] = "Invalid game progress was reset to Level 1."
    level_number = 1

  if not isinstance(session.get("hack_me_run_id"), str):
    session["hack_me_run_id"] = secrets.token_urlsafe(24)
    session["hack_me_level"] = 1
    session["hack_me_earned"] = 0
    session.pop("hack_me_last_command", None)
    session.pop("hack_me_last_output", None)
    level_number = 1

  if level_number <= len(HACK_ME_LEVELS):
    level = HACK_ME_LEVELS[level_number - 1]
  else:
    level = None

  return render_template(
      "hack_me.html",
      level=level,
      levels=HACK_ME_LEVELS,
      level_number=level_number,
      total_points=sum(item["points"] for item in HACK_ME_LEVELS),
      run_points=session.get("hack_me_earned", 0),
      terminal_command=session.get("hack_me_last_command"),
      terminal_output=session.get("hack_me_last_output"),
      notice=session.pop("hack_me_notice", None),
  )


@app.route("/api/news")
def static_news():
  return jsonify(
      [
          {
              "title": "Keep software and devices up to date",
              "source": "CISA",
              "url": "https://www.cisa.gov/secure-our-world",
          },
          {
              "title": "Recognize and report phishing",
              "source": "CISA",
              "url": "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing",
          },
          {
              "title": "Use strong passwords and a password manager",
              "source": "CISA",
              "url": "https://www.cisa.gov/secure-our-world/use-strong-passwords",
          },
      ]
  )


@app.route("/api/live-news")
def live_news():
  api_key = os.environ.get("NEWS_API_KEY")
  if not api_key:
    return jsonify({"error": "NewsAPI is not configured."}), 503

  query = urlencode(
      {
          "q": "cybersecurity",
          "language": "en",
          "pageSize": 20,
          "apiKey": api_key,
      }
  )
  try:
    with urlopen(
        f"https://newsapi.org/v2/everything?{query}",
        timeout=10,
    ) as response:
      payload = json.loads(response.read())
  except (HTTPException, OSError, json.JSONDecodeError):
    return jsonify({"error": "NewsAPI is temporarily unavailable."}), 502

  if not isinstance(payload, dict) or payload.get("status") != "ok":
    return jsonify({"error": "NewsAPI returned an error."}), 502

  payload_articles = payload.get("articles")
  if not isinstance(payload_articles, list):
    return jsonify({"error": "NewsAPI returned an invalid response."}), 502

  articles = []
  for article in payload_articles:
    if not isinstance(article, dict):
      continue
    title = article.get("title")
    url = article.get("url")
    source = article.get("source")
    source_name = source.get("name") if isinstance(source, dict) else None
    try:
      parsed_url = urlparse(url) if isinstance(url, str) else None
    except ValueError:
      continue
    if (
        isinstance(title, str)
        and title.strip()
        and isinstance(source_name, str)
        and source_name.strip()
        and parsed_url is not None
        and parsed_url.scheme.lower() in {"http", "https"}
        and parsed_url.netloc
    ):
      articles.append(
          {
              "title": title.strip(),
              "source": source_name.strip(),
              "url": url,
          }
      )

  return jsonify(articles)


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


@app.route("/cp-shop", methods=["GET", "POST"])
@login_required
def cp_shop():
  items_by_code = {item["code"]: item for item in CP_SHOP_ITEMS}
  if request.method == "POST":
    validate_csrf_token()
    item = items_by_code.get(request.form.get("item_code", ""))
    recipient_name = request.form.get("recipient_name", "").strip()
    shipping_address = request.form.get("shipping_address", "").strip()
    if item is None:
      abort(400, description="Select a valid CP Shop item.")
    if (
        not recipient_name
        or len(recipient_name) > 100
        or not shipping_address
        or len(shipping_address) > 500
    ):
      flash(
          "Enter a recipient name (up to 100 characters) and a shipping "
          "address (up to 500 characters).",
          "error",
      )
      return redirect(url_for("cp_shop"))

    with get_db_connection() as connection:
      debit = connection.execute(
          "UPDATE users SET cyberhacks_points = cyberhacks_points - ? "
          "WHERE id = ? AND cyberhacks_points >= ?",
          (item["points"], g.current_user["id"], item["points"]),
      )
      if debit.rowcount != 1:
        flash(
            f"Not enough CP for the {item['name']}. "
            f"It costs {item['points']:,} CP.",
            "error",
        )
      else:
        connection.execute(
            """
            INSERT INTO cp_shop_orders
                (user_id, item_code, item_name, points_spent, recipient_name,
                 shipping_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                g.current_user["id"],
                item["code"],
                item["name"],
                item["points"],
                recipient_name,
                shipping_address,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        flash(
            f"Order placed for {item['name']}! It is pending manual fulfilment.",
            "success",
        )
    return redirect(url_for("cp_shop"))

  with get_db_connection() as connection:
    orders = connection.execute(
        """
        SELECT item_name, points_spent, status, created_at, fulfilled_at
        FROM cp_shop_orders
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (g.current_user["id"],),
    ).fetchall()
  return render_template("cp_shop.html", items=CP_SHOP_ITEMS, orders=orders)


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
    orders = connection.execute(
        """
        SELECT o.id, o.item_name, o.points_spent, o.recipient_name,
               o.shipping_address, o.status, o.created_at, o.fulfilled_at,
               u.username
        FROM cp_shop_orders AS o
        JOIN users AS u ON u.id = o.user_id
        ORDER BY o.status = 'pending' DESC, o.created_at DESC, o.id DESC
        """
    ).fetchall()
  return render_template(
      "admin_dashboard.html",
      user=g.current_user,
      users=users,
      orders=orders,
      available_roles=AVAILABLE_ROLES,
  )


@app.route("/admin/cp-shop-orders/<int:order_id>/fulfill", methods=["POST"])
@admin_required
def fulfill_cp_shop_order(order_id):
  validate_csrf_token()
  with get_db_connection() as connection:
    result = connection.execute(
        """
        UPDATE cp_shop_orders
        SET status = 'fulfilled', fulfilled_at = ?
        WHERE id = ? AND status = 'pending'
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            order_id,
        ),
    )
    if result.rowcount == 0:
      exists = connection.execute(
          "SELECT 1 FROM cp_shop_orders WHERE id = ?",
          (order_id,),
      ).fetchone()
      if exists is None:
        abort(404)
      flash("That order has already been marked fulfilled.", "info")
    else:
      flash("Order marked as fulfilled.", "success")
  return redirect(url_for("admin_dashboard"))


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