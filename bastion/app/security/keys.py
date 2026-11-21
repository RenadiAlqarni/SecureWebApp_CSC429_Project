"""
Key management.

Keys are read from environment variables when set (how you would do it in
production, e.g. from a secrets manager). Otherwise a random key is generated
on first run and written to the instance/ folder with file mode 600 (owner
read/write only). instance/ is listed in .gitignore so keys never reach Git.
"""
import os


def load_or_create_key(path, factory, env=None):
    if env and os.environ.get(env):
        return os.environ[env].encode("ascii")

    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read().strip()

    key = factory()
    # O_EXCL: fail instead of overwriting if another process created it first.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key
