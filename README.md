# Trove activation server

Binds each Trove license key to one computer and starts its 1-year clock.
Everything needed to run it is in this folder; the only thing you add is the private key,
as a secret, at deploy time.

| File | Purpose |
|---|---|
| `app.py` | The server (FastAPI) |
| `db.py` | Storage: Postgres/Neon via `DATABASE_URL`, or SQLite locally |
| `admin.py` | Support tool: stats, look up, move, revoke, extend keys |
| `smoke_test.py` | Checks a deployed server without using up a real key |
| `Dockerfile` | Container build (listens on Render's `$PORT`) |
| `render.yaml` | One-click Render setup (web service; activations stored in Neon) |
| `requirements.txt` | Python dependencies |
| `.gitignore` / `.dockerignore` | Keep `*.pem`, `*.db` and keys out of git and the image |

## Deploy on Render with Neon (about 15 minutes)

Activations are stored in your **Neon Postgres** database, so Render needs no disk.

1. **Push this folder to a private GitHub repo** (check `git status`: no `.pem`, `.db` or keys):
   ```bash
   cd Trove_activation_server
   git init && git add . && git status
   git commit -m "Trove activation server"
   git remote add origin git@github.com:<you>/trove-activation.git && git push -u origin main
   ```
2. **Render → New → Blueprint** (uses `render.yaml`) or **New → Web Service** (Docker) → pick the repo.
3. **Environment → Environment Variables:** add `DATABASE_URL` = your Neon connection string
   (Neon console → Connect → copy the `postgresql://…` string). Never put it in the repo.
4. **Environment → Secret Files:** add `trove_private_key.pem` with the full contents of
   `Trove_licensing/trove_private_key.pem` (including the BEGIN/END lines).
5. **Manual Deploy → Deploy latest commit.** The log should show
   `[trove] using private key from /etc/secrets/…` and `[trove] storage: Postgres at …neon.tech`.
6. **Check it:** `python smoke_test.py https://<your-service>.onrender.com` → `SERVER OK`.
7. **Build the installer** with that address: `build_trove_windows.bat https://<your-service>.onrender.com`.

Plan: the free Render plan works with Neon but sleeps when idle, so a first activation can take
30–60 s (the app waits and says so). A paid instance stays awake.

## Day-to-day support

Open the service's **Shell** tab on Render:
```bash
python admin.py stats                     # activated / revoked counts
python admin.py list                      # recent activations: key id, device, expiry
python admin.py show TRV-XXXXXXXXXXXX     # one key + its history
python admin.py reset TRV-XXXXXXXXXXXX    # customer changed PC: allow one new activation (same expiry)
python admin.py revoke TRV-XXXXXXXXXXXX   # lock it everywhere (the app locks within a day)
python admin.py extend TRV-XXXXXXXXXXXX 30
```

## Backups (important)

- **The Neon database** records which PC owns each key. Neon keeps history and lets you restore to a
  point in time (Branches / Restore); on paid Neon plans the restore window is longer.
- **The private key** must also be backed up offline. Without it no new activation can be signed;
  if it leaks, anyone can create keys.

## Run locally (testing)

```bash
pip install -r requirements.txt
cp ../Trove_licensing/trove_private_key.pem .     # git-ignored
TROVE_DB=./activations.db uvicorn app:app --port 10000      # SQLite; or set DATABASE_URL to use Neon
python smoke_test.py http://127.0.0.1:10000
```

## API

- `POST /v1/activate {key, machine_id, app_version?, device_name?}` → `{certificate, key_id, activated_at, expires_at}`;
  400 bad key · 403 revoked/expired · 409 already active on another computer
- `POST /v1/validate {certificate}` → `{ok, expires_at}`; 403 if moved/revoked
- `GET /health` → `{"ok": true}`
