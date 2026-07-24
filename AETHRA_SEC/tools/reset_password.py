"""Reset an AETHRA-SEC user's password from the command line.

Passwords are stored as one-way bcrypt hashes and cannot be recovered, but an
administrator with database access can set a new one.  This helper connects to
the same MySQL database the app uses (reading credentials from ``.env`` /
``config.py``), hashes the new password with bcrypt, and updates the account -
also clearing any lockout so the user can log straight in.

Run it from the AETHRA_SEC folder:

    # Reset the built-in admin back to the default password:
    python tools/reset_password.py

    # Reset a specific user to a password you choose:
    python tools/reset_password.py --user admin --password "NewPass@123"

If --password is omitted you'll be prompted to type it (hidden).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

# Make sure we can import the app's config/password modules when run from tools/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONFIG  # noqa: E402

try:
    import mysql.connector  # noqa: E402
except Exception:  # pragma: no cover
    print("ERROR: mysql-connector-python is not installed. Run:\n"
          "    pip install -r requirements.txt")
    raise SystemExit(1)

try:
    import bcrypt  # noqa: E402
except Exception:  # pragma: no cover
    print("ERROR: bcrypt is not installed. Run:\n    pip install bcrypt")
    raise SystemExit(1)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8")[:72], bcrypt.gensalt(rounds=12)).decode("utf-8")


def reset(username: str, new_password: str) -> int:
    cfg = CONFIG.database
    try:
        conn = mysql.connector.connect(**cfg.connection_kwargs(include_db=True))
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not connect to MySQL ({exc}).")
        print("Check that MySQL is running and your .env credentials are correct.")
        return 1

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, role FROM users WHERE username = %s",
                       (username,))
        user = cursor.fetchone()
        if not user:
            print(f"ERROR: no user named '{username}' exists.")
            cursor.execute("SELECT username, role FROM users ORDER BY username")
            existing = cursor.fetchall()
            if existing:
                print("Existing accounts:")
                for u in existing:
                    print(f"  - {u['username']} ({u['role']})")
            return 1

        cursor.execute(
            "UPDATE users SET password_hash = %s, status = 'active', "
            "failed_attempts = 0, locked_until = NULL WHERE id = %s",
            (hash_password(new_password), user["id"]),
        )
        conn.commit()
        print(f"SUCCESS: password reset for '{username}' ({user['role']}).")
        print("The account is now active and unlocked. You can log in with the "
              "new password.")
        return 0
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset an AETHRA-SEC password.")
    parser.add_argument("--user", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", default=None,
                        help="New password (prompted if omitted)")
    args = parser.parse_args()

    new_password = args.password
    if not new_password:
        new_password = getpass.getpass(f"New password for '{args.user}': ")
        confirm = getpass.getpass("Confirm new password: ")
        if new_password != confirm:
            print("ERROR: passwords did not match.")
            return 1
    if len(new_password) < 8:
        print("ERROR: password must be at least 8 characters.")
        return 1
    return reset(args.user, new_password)


if __name__ == "__main__":
    raise SystemExit(main())
