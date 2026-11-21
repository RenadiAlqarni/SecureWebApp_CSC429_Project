"""
Print what is actually stored in the database for each user.

    python scripts/inspect_db.py --mode vulnerable
    python scripts/inspect_db.py --mode secure

Vulnerable: 32-character MD5 hashes and plain-text email addresses.
Secure:     $2b$12$... bcrypt hashes and Fernet ciphertext (gAAAAA...).
"""
import argparse
import os
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["secure", "vulnerable"], required=True)
    args = parser.parse_args()

    path = os.path.join(ROOT, "instance", f"{args.mode}.db")
    if not os.path.exists(path):
        raise SystemExit(f"No database yet at {path}. Start the app once with --mode {args.mode}.")

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT username, role, password_hash, email FROM users ORDER BY id").fetchall()

    print(f"\nusers table in {args.mode}.db\n" + "=" * 72)
    for r in rows:
        print(f"username : {r['username']}  (role: {r['role']})")
        print(f"password : {r['password_hash']}")
        print(f"email    : {r['email']}")
        print("-" * 72)
    conn.close()


if __name__ == "__main__":
    main()
