"""Trove activation server — binds each license key to one computer and starts its year.

  POST /v1/activate   {key, machine_id, app_version?, device_name?}
       -> 200 {certificate, key_id, activated_at, expires_at}
       -> 400 invalid key | 403 revoked | 409 already active on another computer
  POST /v1/validate   {certificate}  -> 200 {ok, expires_at} | 403 revoked
  GET  /health

The certificate is an RS256 token (same Trove key pair) containing the key id, the
hashed machine id and the expiry. The app verifies it offline on every start.

Config (env vars):
  TROVE_PRIVATE_KEY_PATH   path to trove_private_key.pem   (or TROVE_PRIVATE_KEY = PEM text)
  TROVE_DB                 SQLite file (default ./activations.db)
Run:  uvicorn app:app --host 0.0.0.0 --port 8090
"""
import datetime as dt
import os
import sqlite3
import threading
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

HERE = Path(__file__).resolve().parent


def _load_private_key() -> str:
    """TROVE_PRIVATE_KEY (PEM text) > TROVE_PRIVATE_KEY_PATH (e.g. a Render Secret File)
    > ./trove_private_key.pem (local testing; git-ignored) > ../Trove_licensing (dev machine)."""
    if os.environ.get("TROVE_PRIVATE_KEY"):
        return os.environ["TROVE_PRIVATE_KEY"]
    for p in (os.environ.get("TROVE_PRIVATE_KEY_PATH"), HERE / "trove_private_key.pem",
              HERE.parent / "Trove_licensing" / "trove_private_key.pem"):
        if p and Path(p).is_file():
            return Path(p).read_text()
    raise SystemExit("No private key: set TROVE_PRIVATE_KEY_PATH (Render Secret File) or TROVE_PRIVATE_KEY.")


_pem = _load_private_key()
PRIVATE_KEY = _pem.encode()
PUBLIC_KEY = serialization.load_pem_private_key(PRIVATE_KEY, password=None).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
DB_PATH = os.environ.get("TROVE_DB", str(HERE / "activations.db"))

_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.execute("""CREATE TABLE IF NOT EXISTS activations (
    key_id TEXT PRIMARY KEY, machine_id TEXT NOT NULL, device_name TEXT, app_version TEXT,
    activated_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT, activations INTEGER NOT NULL DEFAULT 1)""")
_db.execute("""CREATE TABLE IF NOT EXISTS events (
    at TEXT, key_id TEXT, machine_id TEXT, ip TEXT, outcome TEXT)""")
_db.commit()

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


def _log(key_id, machine_id, ip, outcome):
    _db.execute("INSERT INTO events VALUES (?,?,?,?,?)", (_now().isoformat(), key_id, machine_id, ip, outcome))


def _certificate(key_id, machine_id, activated_at: dt.datetime, expires_at: dt.datetime) -> str:
    return jwt.encode({"iss": "trove", "typ": "activation", "kid": key_id, "mid": machine_id,
                       "act": int(activated_at.timestamp()), "iat": _now(), "exp": expires_at},
                      PRIVATE_KEY, algorithm="RS256")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/v1/activate")
def activate(body: ActivateIn, request: Request):
    ip = request.client.host if request.client else "?"
    try:
        lic = jwt.decode(body.key.strip(), PUBLIC_KEY, algorithms=["RS256"], options={"require": ["kid"]})
        if lic.get("iss") != "trove" or lic.get("typ") != "license":
            raise jwt.InvalidTokenError("not a Trove license")
    except jwt.InvalidTokenError:
        with _lock:
            _log(None, body.machine_id, ip, "invalid_key"); _db.commit()
        raise HTTPException(400, "This license key isn't valid. Check that you copied the whole key.")
    key_id, days = lic["kid"], int(lic.get("days", 365))
    with _lock:
        row = _db.execute("SELECT machine_id, activated_at, expires_at, revoked FROM activations WHERE key_id=?",
                          (key_id,)).fetchone()
        now = _now()
        if row is None:
            activated, expires = now, now + dt.timedelta(days=days)
            _db.execute("INSERT INTO activations (key_id, machine_id, device_name, app_version, activated_at, expires_at, last_seen) "
                        "VALUES (?,?,?,?,?,?,?)", (key_id, body.machine_id, body.device_name, body.app_version,
                                                   activated.isoformat(), expires.isoformat(), now.isoformat()))
            outcome = "activated"
        else:
            bound, act_s, exp_s, revoked = row
            if revoked:
                _log(key_id, body.machine_id, ip, "revoked"); _db.commit()
                raise HTTPException(403, "This license key has been revoked. Please contact support.")
            if bound == "__unbound__":
                # Support reset the key (admin.py reset): bind it to this computer, keep the original expiry.
                _db.execute("UPDATE activations SET machine_id=?, device_name=? WHERE key_id=?",
                            (body.machine_id, body.device_name, key_id))
                bound = body.machine_id
            if bound != body.machine_id:
                _log(key_id, body.machine_id, ip, "other_device"); _db.commit()
                raise HTTPException(409, "This key is already activated on another computer. "
                                         "Contact support to move it to this one.")
            # Same computer (e.g. reinstall): same expiry — the year doesn't restart.
            activated, expires = dt.datetime.fromisoformat(act_s), dt.datetime.fromisoformat(exp_s)
            _db.execute("UPDATE activations SET last_seen=?, activations=activations+1, app_version=? WHERE key_id=?",
                        (now.isoformat(), body.app_version, key_id))
            outcome = "reactivated"
        _log(key_id, body.machine_id, ip, outcome)
        _db.commit()
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
    with _lock:
        row = _db.execute("SELECT revoked, machine_id FROM activations WHERE key_id=?", (cert["kid"],)).fetchone()
        if not row or row[0] or row[1] != cert["mid"]:
            raise HTTPException(403, "This activation is no longer valid.")
        _db.execute("UPDATE activations SET last_seen=? WHERE key_id=?", (_now().isoformat(), cert["kid"]))
        _db.commit()
    return {"ok": True, "expires_at": dt.datetime.fromtimestamp(cert["exp"], dt.timezone.utc).isoformat()}
