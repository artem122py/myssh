#!/usr/bin/env python3
# serve_sftp_test.py — тестовый SSH+SFTP-сервер со стабильным host key.
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from myssh import SSHServer, SSHKeys, Key, _get_username

hk_path = os.path.expanduser("~/.ssh/myssh_host_key")
user_key_path = os.path.expanduser("~/.ssh/myssh_test")

hk_single = Key.load(hk_path)
host_keys = SSHKeys(seed=hk_single.bytes(), comment="host@myssh")
print(f"host fp: {host_keys.public_key.fingerprint}")

user_key = Key.load(user_key_path)
print(f"user fp: {user_key.fingerprint}")

user = _get_username()
PORT = int(os.environ.get("PORT", "2508"))

srv = SSHServer(
    host_keys=host_keys,
    addr=("127.0.0.1", PORT),
    users={user: user_key, "alice": user_key},
    verbose=True,
    shell_mode="auto",
)
srv.sftp_root = os.path.expanduser("~")
print(f"sftp root = {srv.sftp_root}")
print(f"listen on 127.0.0.1:{PORT}, user={user}")
print("Ctrl-C для выхода")
try:
    srv.serve_forever()
except KeyboardInterrupt:
    srv.stop()
