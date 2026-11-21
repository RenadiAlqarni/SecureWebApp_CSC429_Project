"""
Start Bastion.

    python run.py --mode secure        # https://127.0.0.1:5443  (default)
    python run.py --mode vulnerable    # http://127.0.0.1:5000
    python run.py --mode secure --reset-db   # start from an empty database

Debug mode is deliberately never enabled, not even in the vulnerable build:
the Werkzeug debugger allows running arbitrary Python from the browser.
"""
import argparse

from app import create_app
from app.security.tls import build_ssl_context, ensure_self_signed_cert


def main():
    parser = argparse.ArgumentParser(description="Run the Bastion demo app.")
    parser.add_argument("--mode", choices=["secure", "vulnerable"], default="secure")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Keep 127.0.0.1 so the app is reachable only from this computer.")
    parser.add_argument("--port", type=int, help="Defaults to 5443 (secure) or 5000 (vulnerable).")
    parser.add_argument("--reset-db", action="store_true", help="Delete this mode's database first.")
    args = parser.parse_args()

    app = create_app(args.mode, reset_db=args.reset_db)

    if args.mode == "secure":
        cert, key = ensure_self_signed_cert(app.instance_path)
        port = args.port or 5443
        print(f"\n  Bastion - SECURE build\n  https://{args.host}:{port}\n"
              "  (self-signed certificate: your browser will ask you to accept it once)\n")
        app.run(host=args.host, port=port, ssl_context=build_ssl_context(cert, key), debug=False)
    else:
        port = args.port or 5000
        print(f"\n  Bastion - VULNERABLE build (demo only, do not expose)\n  http://{args.host}:{port}\n")
        app.run(host=args.host, port=port, debug=False)


if __name__ == "__main__":
    main()
