"""Check a deployed activation server without using up a real key.

  python smoke_test.py https://trove-activation.onrender.com
"""
import json
import sys
import urllib.error
import urllib.request

base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:10000").rstrip("/")


def call(path, body=None):
    req = urllib.request.Request(base + path, method="POST" if body else "GET",
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:      # 90 s: allows for a cold start
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


ok = True
s, b = call("/health")
print(f"/health            -> {s} {b}"); ok &= s == 200 and b.get("ok")
s, b = call("/v1/activate", {"key": "not-a-real-key", "machine_id": "0" * 40})
print(f"invalid key        -> {s} {b.get('detail')}"); ok &= s == 400
s, b = call("/v1/validate", {"certificate": "not-a-cert"})
print(f"invalid cert       -> {s} {b.get('detail')}"); ok &= s == 400
print("\nSERVER OK" if ok else "\nSOMETHING IS WRONG — check the Render logs")
sys.exit(0 if ok else 1)
