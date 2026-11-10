"""Admin tool for the activation database.

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
import sqlite3
import sys
from pathlib import Path

DB = os.environ.get("TROVE_DB", str(Path(__file__).resolve().parent / "activations.db"))
db = sqlite3.connect(DB)
cmd, args = (sys.argv[1] if len(sys.argv) > 1 else "stats"), sys.argv[2:]

if cmd == "stats":
    total, revoked = db.execute("SELECT COUNT(*), COALESCE(SUM(revoked),0) FROM activations").fetchone()
    print(f"activated keys: {total}  revoked: {revoked}")
    for outcome, n in db.execute("SELECT outcome, COUNT(*) FROM events GROUP BY outcome"):
        print(f"  {outcome:14} {n}")
elif cmd == "list":
    limit = int(args[args.index("--limit") + 1]) if "--limit" in args else 50
    for r in db.execute("SELECT key_id, device_name, activated_at, expires_at, revoked FROM activations "
                        "ORDER BY activated_at DESC LIMIT ?", (limit,)):
        print(" | ".join(str(x) for x in r))
elif cmd == "show":
    r = db.execute("SELECT * FROM activations WHERE key_id=?", (args[0],)).fetchone()
    print(r or "not activated yet")
    for e in db.execute("SELECT * FROM events WHERE key_id=? ORDER BY at", (args[0],)):
        print("  ", e)
elif cmd == "reset":
    # Free the machine binding but keep the original expiry; the next activation re-binds it.
    r = db.execute("SELECT activated_at, expires_at FROM activations WHERE key_id=?", (args[0],)).fetchone()
    if not r:
        print("not activated yet")
    else:
        db.execute("UPDATE activations SET machine_id='__unbound__' WHERE key_id=?", (args[0],))
        db.commit(); print(f"{args[0]} can now be activated on a new computer (expires {r[1]})")
elif cmd in ("revoke", "unrevoke"):
    db.execute("UPDATE activations SET revoked=? WHERE key_id=?", (1 if cmd == "revoke" else 0, args[0]))
    db.commit(); print(f"{cmd}d {args[0]}")
elif cmd == "extend":
    r = db.execute("SELECT expires_at FROM activations WHERE key_id=?", (args[0],)).fetchone()
    new = dt.datetime.fromisoformat(r[0]) + dt.timedelta(days=int(args[1]))
    db.execute("UPDATE activations SET expires_at=? WHERE key_id=?", (new.isoformat(), args[0]))
    db.commit(); print(f"{args[0]} now expires {new.isoformat()}")
else:
    print(__doc__)
