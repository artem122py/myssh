#!/usr/bin/env python3
# mysftp.py — интерактивный SFTP-клиент на базе myssh.
# Использование:
#   python3 mysftp.py user@host -p PORT -i KEYFILE
import sys, os, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from myssh import SSH, Key, SFTPClient, _get_username


def main():
    ap = argparse.ArgumentParser(description="mysftp — SFTP-клиент (myssh)")
    ap.add_argument("target", help="user@host")
    ap.add_argument("-p", "--port", type=int, default=22)
    ap.add_argument("-i", "--identity", default="~/.ssh/id_ed25519",
                    help="private key file")
    ap.add_argument("-o", "--option", action="append", default=[],
                    help="extra SSH options (пока игнорируются)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if "@" in args.target:
        user, host = args.target.split("@", 1)
    else:
        user, host = _get_username(), args.target

    keyfile = os.path.expanduser(args.identity)
    if not os.path.exists(keyfile):
        print(f"key not found: {keyfile}", file=sys.stderr)
        return 1

    try:
        key = Key.load(keyfile)
    except Exception as e:
        print(f"key load failed: {e}", file=sys.stderr)
        return 1

    print(f"Connecting to {host}:{args.port} as {user}...")
    try:
        ssh = SSH(key, key, (host, args.port),
                  known_hosts=None, strict=False,
                  verbose=args.verbose)
        ssh.authenticate(user)
    except Exception as e:
        print(f"SSH error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    sftp = SFTPClient(ssh)
    try:
        sftp.open_session()
    except Exception as e:
        print(f"SFTP error: {type(e).__name__}: {e}", file=sys.stderr)
        ssh.close()
        return 1

    try:
        sftp.run_cli(host=host, port=args.port)
    finally:
        try:
            ssh.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
