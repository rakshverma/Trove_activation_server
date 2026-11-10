"""Admin tool for activations (works with Neon/Postgres via DATABASE_URL, or local SQLite).

  python admin.py stats
  python admin.py list [--limit 50]
  python admin.py show TRV-XXXXXXXXXXXX
  python admin.py reset TRV-XXXXXXXXXXXX     # let the key activate on a new computer (keeps its expiry)
  python admin.py revoke TRV-XXXXXXXXXXXX    # block the key everywhere
  python admin.py unrevoke TRV-XXXXXXXXXXXX
  python admin.py extend TRV-XXXXXXXXXXXX 30 # add days
"""
import datetime as dt
import os
import sys
from pathlib import Path

import db

db.init(os.environ.get("TROVE_DB", str(Path(__file__).resolve().parent / "activations.db")))
cmd, args = (sys.argv[1] if len(sys.argv) > 1 else "help"), sys.argv[2:]


def need_key():
    if not args:
        sys.exit("Give a key id, e.g. TRV-6D5B068C791A")
    return args[0].strip().upper()


with db.tx() as c:
    if cmd == "stats":
        total, revoked = c.execute("SELECT COUNT(*), COALESCE(SUM(revoked), 0) FROM activations").fetchone()
        print(f"activated keys: {total}  revoked: {revoked}")
        for outcome, n in c.execute("SELECT outcome, COUNT(*) FROM events GROUP BY outcome ORDER BY outcome").fetchall():
            print(f"  {outcome:14} {n}")
    elif cmd == "list":
        limit = int(args[args.index("--limit") + 1]) if "--limit" in args else 50
        for r in c.execute("SELECT key_id, device_name, activated_at, expires_at, revoked FROM activations "
                           "ORDER BY activated_at DESC LIMIT ?", (limit,)).fetchall():
            print(" | ".join(str(x) for x in r))
    elif cmd == "show":
        kid = need_key()
        r = c.execute("SELECT * FROM activations WHERE key_id=?", (kid,)).fetchone()
        print(r or "not activated yet")
        for e in c.execute("SELECT * FROM events WHERE key_id=? ORDER BY at", (kid,)).fetchall():
            print("  ", e)
    elif cmd == "reset":
        kid = need_key()
        r = c.execute("SELECT expires_at FROM activations WHERE key_id=?", (kid,)).fetchone()
        if not r:
            print("not activated yet")
        else:
            # Free the machine binding but keep the original expiry; the next activation re-binds it.
            c.execute("UPDATE activations SET machine_id='__unbound__' WHERE key_id=?", (kid,))
            print(f"{kid} can now be activated on a new computer (expires {r[0]})")
    elif cmd in ("revoke", "unrevoke"):
        kid = need_key()
        c.execute("UPDATE activations SET revoked=? WHERE key_id=?", (1 if cmd == "revoke" else 0, kid))
        print(f"{cmd}d {kid}" if c.rowcount else f"{kid} isn't activated yet")
    elif cmd == "extend":
        kid = need_key()
        r = c.execute("SELECT expires_at FROM activations WHERE key_id=?", (kid,)).fetchone()
        if not r:
            sys.exit(f"{kid} isn't activated yet")
        new = dt.datetime.fromisoformat(r[0]) + dt.timedelta(days=int(args[1]))
        c.execute("UPDATE activations SET expires_at=? WHERE key_id=?", (new.isoformat(), kid))
        print(f"{kid} now expires {new.isoformat()}")
    else:
        print(__doc__)
