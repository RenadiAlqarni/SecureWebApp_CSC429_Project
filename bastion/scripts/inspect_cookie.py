"""
Try to read a session cookie WITHOUT the server's key - what an attacker who
stole the cookie could see.

    python scripts/inspect_cookie.py "<value of the session cookie>"

Vulnerable build: Flask's default cookie is "payload.timestamp.signature".
The payload is just base64 (optionally zlib-compressed) JSON, so it decodes.
Secure build: the cookie is a Fernet token. Without the key it is random bytes.
"""
import base64
import json
import sys
import zlib


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    cookie = sys.argv[1].strip().strip('"')

    if cookie.startswith("gAAAAA"):
        raw = b64url_decode(cookie)
        print("Fernet token (secure build)")
        print(f"  version byte : 0x{raw[0]:02x}")
        print(f"  timestamp    : {int.from_bytes(raw[1:9], 'big')} (only metadata is visible)")
        print(f"  ciphertext   : {raw[25:-32].hex()[:64]}...")
        print("  -> contents are encrypted (AES) and authenticated (HMAC). Unreadable without the key.")
        return

    compressed = cookie.startswith(".")
    payload = cookie.lstrip(".").split(".")[0]
    data = b64url_decode(payload)
    if compressed:
        data = zlib.decompress(data)
    print("Flask signed cookie (vulnerable build) - decoded without any key:")
    print(json.dumps(json.loads(data), indent=2))
    print("  -> signed is not encrypted: anyone holding the cookie can read it.")


if __name__ == "__main__":
    main()
