# Trove activation server

Binds each Trove license key to one computer and starts its 1-year clock.
Everything needed to run it is in this folder; the only thing you add is the private key,
as a secret, at deploy time.

| File | Purpose |
|---|---|
| `app.py` | The server (FastAPI + SQLite) |
| `admin.py` | Support tool: stats, look up, move, revoke, extend keys |
| `smoke_test.py` | Checks a deployed server without using up a real key |
| `Dockerfile` | Container build (listens on Render's `$PORT`) |
| `render.yaml` | One-click Render setup: web service + 1 GB persistent disk |
| `requirements.txt` | Python dependencies |
| `.gitignore` / `.dockerignore` | Keep `*.pem`, `*.db` and keys out of git and the image |

## Deploy on Render (about 15 minutes)

1. **Create a private GitHub repo** containing *only this folder's files*. Check `git status`
   before pushing: no `.pem`, no `.db`, no `keys.txt`.
   ```bash
   cd Trove_activation_server
   git init && git add . && git status   # make sure no secret files are listed
   git commit -m "Trove activation server"
   git remote add origin git@github.com:<you>/trove-activation.git && git push -u origin main
   ```
2. **Render → New → Blueprint →** pick the repo. Render reads `render.yaml` and creates the
   `trove-activation` web service (Starter plan) with a 1 GB disk at `/data`.
   The free plan won't work: it has no persistent disk (activations would be forgotten on every
   restart) and it sleeps when idle.
3. **Add the private key as a Secret File:** service → *Environment* → *Secret Files* → add
   `trove_private_key.pem` and paste the contents of `Trove_licensing/trove_private_key.pem`.
   It's mounted at `/etc/secrets/trove_private_key.pem`, which is what `TROVE_PRIVATE_KEY_PATH`
   points to. Then **Manual Deploy → Deploy latest commit**.
4. **Check it:**
   ```bash
   python smoke_test.py https://trove-activation.onrender.com
   ```
   → `SERVER OK`
5. **Build the installer** with that address (on Windows):
   ```bat
   build_trove_windows.bat https://trove-activation.onrender.com
   ```

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

- **`/data/activations.db`** records which PC owns each key. Download it from the Shell
  regularly (e.g. `sqlite3 /data/activations.db ".backup /data/backup.db"`, then copy it off).
- **The private key** must also be backed up offline. Without it no new activation can be signed;
  if it leaks, anyone can create keys.

## Run locally (testing)

```bash
pip install -r requirements.txt
cp ../Trove_licensing/trove_private_key.pem .     # git-ignored
TROVE_DB=./activations.db uvicorn app:app --port 10000
python smoke_test.py http://127.0.0.1:10000
```

## API

- `POST /v1/activate {key, machine_id, app_version?, device_name?}` → `{certificate, key_id, activated_at, expires_at}`;
  400 bad key · 403 revoked/expired · 409 already active on another computer
- `POST /v1/validate {certificate}` → `{ok, expires_at}`; 403 if moved/revoked
- `GET /health` → `{"ok": true}`
