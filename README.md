# Cybernews Tracker

A Flask application for tracking cybersecurity news, with account registration,
role-based dashboards, and a discussion forum.

The **Hack Me** page contains a five-level simulated PowerShell puzzle. Its
read-only commands are evaluated by the application and are never run by the
server or browser. Signed-in users earn 1, 3, 5, 10, and 25 Cyberhacks Points
for completing the levels; each replay is a new run and can earn the rewards
again.

On its first startup with a Patrick account present, the application sets
Patrick's Cyberhacks Points balance to 100,000. This one-time initialization
does not overwrite his balance on later restarts.

## Run locally

Requirements: Python 3.12 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP = "web_app"
flask run
```

## NewsAPI

The `/news` page loads local fallback headlines from `/api/news`. Clicking
**Refresh Headlines** requests live cybersecurity headlines from NewsAPI.
Set the `NEWS_API_KEY` environment variable locally or in the hosting provider;
never commit the key to the repository. For local PowerShell use:

```powershell
$env:NEWS_API_KEY = "your_new_api_key"
flask run
```

If an API key has been exposed, revoke it and replace it before deployment.

## Deploying on Render

Render's default service filesystem is ephemeral, so the SQLite database under
`instance/` is recreated or lost when the service is replaced. To persist
accounts, forum content, and sessions:

1. Add a persistent disk to the Render web service and set its mount path to
   `/var/data`.
2. In the service's environment settings, set `DATABASE_PATH` to
   `/var/data/cybernews.sqlite3`.
3. Set `FLASK_SECRET_KEY` to a stable, private random value, and set
   `NEWS_API_KEY` to the replacement NewsAPI key.
4. Deploy/restart the service after saving the environment settings.

The application creates the database directory if needed. Keep the Render
service to one instance and avoid deploying a SQLite database shared by
multiple services. If existing production data is still available, copy its
SQLite file to the persistent disk before switching `DATABASE_PATH`; otherwise
the new persistent database will start empty. Back up the database separately
before modifying the production storage configuration.

The local development environment may contain a starter SQLite database at
`instance/cybernews.sqlite3` with a `Patrick` account in the `Administrator`
role. The `instance/` directory is excluded from version control, so that
database is not deployed from GitHub; a new Render database starts empty. Once
the persistent disk is configured, create a production account using
`flask create-user USERNAME` in the Render service shell. Never add real user
data or reused passwords to this public repository.

To create an account from the command line, run:

```powershell
flask create-user USERNAME
```

Review and replace the contact information in the Impressum before using this
site publicly.
