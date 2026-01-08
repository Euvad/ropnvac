# Simple Availability Planner

Quick Flask app to register users and select days they are available.

Setup (Windows):

1. Create and activate a virtualenv

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the app

```powershell
python app.py
```

3. Open http://127.0.0.1:5000 in your browser.

Notes:
- Register with `name`, `surname`, `rio`, `rank` (PA or GPX) and a `date_limit` (YYYY-MM-DD).
- You can select days between `date_limit` and `date_limit + 90 days`.

Secrets and Git
----------------
- Copy `.env.example` to `.env` and fill secure values; **do not commit** `.env`.
- A `.gitignore` has been added to exclude `.env`, virtual environments, and common artifacts.

Preparing to push
-----------------
- Ensure `.env` is NOT staged/committed. If you accidentally committed secrets, rotate them and remove from history before pushing.
- Run tests (if any) and linting before pushing.
