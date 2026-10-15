# DailyUpdates — Flask deployment-ready project

DailyUpdates is a Flask + SQLite application with admin/user login, announcements, private notes, file uploads, and file preview/edit routes for supported TXT, XLSX, and DOCX files.

## Run locally on Windows CMD

From the project directory:

```bat
python -m venv venv
venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

First-run demo admin: `admin` / `Admin@123`. Change this immediately and do not expose the default account to the public. Set a strong `DAILYUPDATES_SECRET` environment variable for local or hosted use.

## Deploy on Render with persistent data

This repository includes `render.yaml`. It configures a Python web service, Gunicorn, a `/var/data` persistent disk, and environment variables for the database/uploads directory and session secret.

1. Push this project folder to a GitHub repository. Do not commit `dailyupdates.db`, `.env`, or `user_files/`; `.gitignore` excludes them.
2. In Render, choose **New → Blueprint** and connect the GitHub repository containing this `render.yaml`.
3. Review the service and disk configuration, then create it. The included configuration uses Render's paid `starter` web service and a 1 GB persistent disk because a reliable persistent SQLite database and uploaded files require persistent storage. Confirm current pricing in Render before creating resources.
4. Wait for deployment to finish and open the Render-provided URL.
5. Log in and change the demo admin password immediately. Create test accounts and verify updates, notes, uploads, downloads, and edits.
6. Keep backups of `/var/data/dailyupdates.db` and `/var/data/user_files` and `/var/data/uploads`.

### Existing local data migration

The ZIP does not contain your personal database or uploads. To migrate them, securely copy your existing `dailyupdates.db`, `user_files/`, and `uploads/` into the persistent disk at `/var/data` using an approved private transfer method, with the service stopped during the copy. Preserve folder names and permissions. Do not upload the database or private documents to a public Git repository. If you have existing user data, test a backup copy first.

## Important limitations and security notes

- This app uses SQLite. Configure a persistent disk mounted at `/var/data`; otherwise the database and uploaded files can be lost on redeploy/restart on ephemeral hosts.
- A persistent disk is not included in many free hosting tiers. Check provider pricing and limits before deploying; this configuration is not guaranteed to be free.
- Default admin credentials are for first-run testing only. Change them before public use. Add an admin password-change workflow and disable open registration or add CAPTCHA/rate limiting before production.
- Flask debug mode is disabled by default in the hosted start command.
- Upload limit is 10 MB per request. Only allowlisted extensions are accepted.
- Back up database and uploads regularly. A persistent disk is not itself a backup.
- Custom domains can be attached in the host dashboard after the service is deployed.
