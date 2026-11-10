"""Trove activation server — binds each license key to one computer and starts its year.

  POST /v1/activate   {key, machine_id, app_version?, device_name?}
       -> 200 {certificate, key_id, activated_at, expires_at}
       -> 400 invalid key | 403 revoked | 409 already active on another computer
  POST /v1/validate   {certificate}  -> 200 {ok, expires_at} | 403 revoked
  GET  /health

The certificate is an RS256 token (same Trove key pair) containing the key id, the
hashed machine id and the expiry. The app verifies it offline on every start.

Config (env vars):
  DATABASE_URL             Postgres connection string (e.g. Neon). If unset, SQLite at TROVE_DB.
  TROVE_DB                 SQLite file for local use (default ./activations.db)
  TROVE_PRIVATE_KEY_PATH   path to trove_private_key.pem   (or TROVE_PRIVATE_KEY = PEM text;
                           on Render a Secret File under /etc/secrets is found automatically)
Run:  uvicorn app:app --host 0.0.0.0 --port 10000
"""
import datetime as dt
import os
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

import db

HERE = Path(__file__).resolve().parent


def _load_private_key() -> str:
    """TROVE_PRIVATE_KEY (PEM text) > TROVE_PRIVATE_KEY_PATH > any file under /etc/secrets (Render
    Secret Files, whatever its name) containing a private key > local files (testing / dev machine)."""
    if os.environ.get("TROVE_PRIVATE_KEY", "").strip():
        return os.environ["TROVE_PRIVATE_KEY"].replace("\\n", "\n")
    secrets_dir = Path(os.environ.get("TROVE_SECRETS_DIR", "/etc/secrets"))   # Render mounts Secret Files here
    candidates = [os.environ.get("TROVE_PRIVATE_KEY_PATH"), secrets_dir / "trove_private_key.pem"]
    if secrets_dir.is_dir():
        # Render keeps the real files in ..data/ with symlinks on top — look everywhere, any name.
        for f in sorted(secrets_dir.rglob("*")):
            try:
                if f.is_file() and f.stat().st_size < 20000:
                    candidates.append(f)
            except OSError:
                continue
    candidates += [HERE / "trove_private_key.pem", HERE.parent / "Trove_licensing" / "trove_private_key.pem"]
    wrong = []
    for p in candidates:
        if not p or not Path(p).is_file():
            continue
        text = Path(p).read_text(errors="ignore")
        if "PRIVATE KEY-----" in text:
            print(f"[trove] using private key from {p}", flush=True)
            return text
        wrong.append(str(p))
    present = sorted(str(f.relative_to(secrets_dir)) for f in secrets_dir.rglob("*")) if secrets_dir.is_dir() else []
    raise SystemExit(
        "No private key found. On Render open THIS service -> Environment -> Secret Files -> Add Secret File: "
        "filename trove_private_key.pem, contents = the whole key incl. the BEGIN/END PRIVATE KEY lines -> Save, "
        f"then Manual Deploy. (Files under {secrets_dir}: {present or 'none'}"
        + (f"; files without a key: {wrong}" if wrong else "") + ")")


_pem = _load_private_key()
PRIVATE_KEY = _pem.encode()
PUBLIC_KEY = serialization.load_pem_private_key(PRIVATE_KEY, password=None).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
print(f"[trove] storage: {db.init(os.environ.get('TROVE_DB', str(HERE / 'activations.db')))}", flush=True)

app = FastAPI(title="Trove activation")


class ActivateIn(BaseModel):
    key: str = Field(..., max_length=4000)
    machine_id: str = Field(..., min_length=16, max_length=128)
    app_version: str | None = Field(None, max_length=40)
    device_name: str | None = Field(None, max_length=120)


class ValidateIn(BaseModel):
    certificate: str = Field(..., max_length=4000)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _log(c, key_id, machine_id, ip, outcome):
    c.execute("INSERT INTO events (at, key_id, machine_id, ip, outcome) VALUES (?,?,?,?,?)",
              (_now().isoformat(), key_id, machine_id, ip, outcome))


def _certificate(key_id, machine_id, activated_at: dt.datetime, expires_at: dt.datetime) -> str:
    return jwt.encode({"iss": "trove", "typ": "activation", "kid": key_id, "mid": machine_id,
                       "act": int(activated_at.timestamp()), "iat": _now(), "exp": expires_at},
                      PRIVATE_KEY, algorithm="RS256")


@app.get("/health")
def health():
    return {"ok": True}


class _Refuse(Exception):
    def __init__(self, status, detail, outcome):
        self.status, self.detail, self.outcome = status, detail, outcome


@app.post("/v1/activate")
def activate(body: ActivateIn, request: Request):
    ip = request.client.host if request.client else "?"
    try:
        lic = jwt.decode(body.key.strip(), PUBLIC_KEY, algorithms=["RS256"], options={"require": ["kid"]})
        if lic.get("iss") != "trove" or lic.get("typ") != "license":
            raise jwt.InvalidTokenError("not a Trove license")
    except jwt.InvalidTokenError:
        with db.tx() as c:
            _log(c, None, body.machine_id, ip, "invalid_key")
        raise HTTPException(400, "This license key isn't valid. Check that you copied the whole key.")
    key_id, days = lic["kid"], int(lic.get("days", 365))
    now = _now()
    try:
        with db.tx() as c:
            # First activation wins, even if two requests race: only one INSERT succeeds.
            fresh_exp = now + dt.timedelta(days=days)
            c.execute("INSERT INTO activations (key_id, machine_id, device_name, app_version, activated_at, "
                      "expires_at, last_seen) VALUES (?,?,?,?,?,?,?) ON CONFLICT (key_id) DO NOTHING",
                      (key_id, body.machine_id, body.device_name, body.app_version,
                       now.isoformat(), fresh_exp.isoformat(), now.isoformat()))
            if c.rowcount == 1:
                activated, expires, outcome = now, fresh_exp, "activated"
            else:
                bound, act_s, exp_s, revoked = c.execute(
                    "SELECT machine_id, activated_at, expires_at, revoked FROM activations WHERE key_id=?"
                    + (" FOR UPDATE" if db.IS_PG else ""), (key_id,)).fetchone()
                if revoked:
                    raise _Refuse(403, "This license key has been revoked. Please contact support.", "revoked")
                if bound == "__unbound__":
                    # Support reset the key (admin.py reset): bind it to this computer, keep the original expiry.
                    c.execute("UPDATE activations SET machine_id=?, device_name=? WHERE key_id=?",
                              (body.machine_id, body.device_name, key_id))
                    bound = body.machine_id
                if bound != body.machine_id:
                    raise _Refuse(409, "This key is already activated on another computer. "
                                       "Contact support to move it to this one.", "other_device")
                # Same computer (e.g. reinstall): same expiry — the year doesn't restart.
                activated, expires = dt.datetime.fromisoformat(act_s), dt.datetime.fromisoformat(exp_s)
                c.execute("UPDATE activations SET last_seen=?, activations=activations+1, app_version=? "
                          "WHERE key_id=?", (now.isoformat(), body.app_version, key_id))
                outcome = "reactivated"
            _log(c, key_id, body.machine_id, ip, outcome)
    except _Refuse as r:
        with db.tx() as c:
            _log(c, key_id, body.machine_id, ip, r.outcome)
        raise HTTPException(r.status, r.detail)
    if expires <= now:
        raise HTTPException(403, f"This license expired on {expires.date()}. Please renew.")
    return {"certificate": _certificate(key_id, body.machine_id, activated, expires), "key_id": key_id,
            "activated_at": activated.isoformat(), "expires_at": expires.isoformat(), "status": outcome}


@app.post("/v1/validate")
def validate(body: ValidateIn):
    try:
        cert = jwt.decode(body.certificate, PUBLIC_KEY, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(403, "License expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(400, "Invalid certificate.")
    with db.tx() as c:
        row = c.execute("SELECT revoked, machine_id FROM activations WHERE key_id=?", (cert["kid"],)).fetchone()
        if not row or row[0] or row[1] != cert["mid"]:
            raise HTTPException(403, "This activation is no longer valid.")
        c.execute("UPDATE activations SET last_seen=? WHERE key_id=?", (_now().isoformat(), cert["kid"]))
    return {"ok": True, "expires_at": dt.datetime.fromtimestamp(cert["exp"], dt.timezone.utc).isoformat()}
