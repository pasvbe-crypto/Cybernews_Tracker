# Cybernews Tracker

A Flask application for tracking cybersecurity news, with account registration,
role-based dashboards, and a discussion forum.

## Run locally

Requirements: Python 3.12 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP = "web_app"
flask run
```

The repository includes a starter SQLite database at
`instance/cybernews.sqlite3` with a `Patrick` account in the `Administrator`
role. Its password hash is public along with the database; the generated
password is provided separately to the repository owner. Change that password
before using the account, and never add real user data or reused passwords to
this public repository. Other local database and data files are excluded from
version control.

To create an account from the command line, run:

```powershell
flask create-user USERNAME
```

Review and replace the contact information in the Impressum before using this
site publicly.
# Cybernews Tracker

A Flask application for tracking cybersecurity news, with account registration,
role-based dashboards, and a discussion forum.

## Run locally

Requirements: Python 3.12 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP = "web_app"
flask run
```

The SQLite database is created in `instance/cybernews.sqlite3` when the app
starts. The database and local data directories are excluded from version
control; do not commit a database containing user records.

To create an account from the command line, run:

```powershell
flask create-user USERNAME
```

Review and replace the contact information in the Impressum before using this
site publicly.
