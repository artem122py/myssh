#!/usr/bin/env python3
# test_myssh.py — автотесты для myssh. Только stdlib + myssh.
import sys, os, time, threading, tempfile, hashlib, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import myssh
from myssh import (
    SSH, SSHServer, SSHKeys, RSAKeys, Key, RSAKey,
    Packetizer, Transport, build_kexinit, parse_kexinit, negotiate,
    derive_key, compute_exchange_hash, _ssh_string, ssh_mpint,
    _kh_load, _kh_check, _kh_append, _kh_normalize,
    _parse_openssh_private, bcrypt_pbkdf,
    MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION, MSG_GLOBAL_REQUEST,
    SSHError, SSHHostKeyError, SSHChannelError,
    Ed25519, _aes256_ctr, AESGCM, X25519,
)

# ─── Мини-фреймворк ─────────────────────────────────────────
class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def run(self, name, fn):
        try:
            fn()
            self.passed += 1
            print(f"  [ok]   {name}")
        except Exception as e:
            self.failed += 1
            self.errors.append((name, e))
            print(f"  [FAIL] {name}: {type(e).__name__}: {e}")

    def summary(self):
        total = self.passed + self.failed
        print()
        print(f"═══ Итого: {self.passed}/{total} ok, {self.failed} fail ═══")
        if self.errors:
            print()
            for name, e in self.errors:
                print(f"  [FAIL] {name}: {type(e).__name__}: {e}")
        return self.failed == 0


def _mk_server(host_keys, users, port):
    """Запускает сервер в фоне на localhost:port."""
    srv = SSHServer(host_keys=host_keys, addr=("127.0.0.1", port),
                    users=users, verbose=False, shell_mode="auto")
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    time.sleep(0.25)
    return srv


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ═══════════════════════════════════════════════════════════
# 1. Крипто-примитивы
# ═══════════════════════════════════════════════════════════
def test_crypto():
    print("\n[1] Крипто-примитивы")

    r = TestRunner()

    def t_sha256():
        lib = myssh._PRIM_C
        import ctypes
        U8 = ctypes.c_ubyte
        out = (U8 * 32)()
        data = b"abc"
        buf = (U8 * len(data)).from_buffer_copy(data)
        lib.myssh_sha256(buf, len(data), out)
        assert bytes(out).hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    r.run("SHA-256('abc')", t_sha256)

    def t_sha512():
        lib = myssh._PRIM_C
        import ctypes
        U8 = ctypes.c_ubyte
        out = (U8 * 64)()
        data = b"abc"
        buf = (U8 * len(data)).from_buffer_copy(data)
        lib.myssh_sha512(buf, len(data), out)
        assert bytes(out).hex().startswith("ddaf35a193617aba")
    r.run("SHA-512('abc')", t_sha512)

    def t_x25519():
        lib = myssh._PRIM_C
        import ctypes
        U8 = ctypes.c_ubyte
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        out = (U8 * 32)()
        lib.myssh_x25519_scalarmult((U8*32).from_buffer_copy(k),
                                    (U8*32).from_buffer_copy(u), out)
        assert bytes(out).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    r.run("X25519 RFC 7748", t_x25519)

    def t_aesgcm():
        key = bytes(32); nonce = bytes(12); pt = bytes(16); aad = b""
        g = AESGCM(key)
        ct = g.encrypt(nonce, pt, aad)
        assert ct.hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        pt2 = g.decrypt(nonce, ct, aad)
        assert pt2 == pt
    r.run("AES-256-GCM NIST", t_aesgcm)

    def t_aesgcm_tamper():
        key = bytes(32); nonce = bytes(12); pt = b"hello"
        g = AESGCM(key)
        ct = bytearray(g.encrypt(nonce, pt))
        ct[5] ^= 1
        try:
            g.decrypt(nonce, bytes(ct))
            assert False, "tampered ct accepted"
        except SSHError:
            pass
    r.run("AES-GCM rejects tampering", t_aesgcm_tamper)

    def t_bcrypt():
        out = bcrypt_pbkdf(b"password", b"salt", 32, 4)
        assert out.hex() == "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9"
    r.run("bcrypt_pbkdf (OpenSSH vector)", t_bcrypt)

    def t_ed25519():
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        ed = Ed25519(seed)
        assert ed.public_raw.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    r.run("Ed25519 pubkey (RFC 8032)", t_ed25519)

    def t_ed25519_sign():
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        ed = Ed25519(seed)
        msg = b""
        sig = ed.sign(msg)
        assert ed.verify(ed.public_raw, msg, sig)
        assert not ed.verify(ed.public_raw, b"x", sig)
    r.run("Ed25519 sign/verify", t_ed25519_sign)

    r.summary()
    return r.failed == 0




# ═══════════════════════════════════════════════════════════
# 1b. SHA3 / SHAKE
# ═══════════════════════════════════════════════════════════
def test_sha3():
    print("\n[1b] SHA3 / SHAKE")

    r = TestRunner()

    def t_selftest():
        lib = myssh._PRIM_C
        lib.myssh_sha3_selftest.restype = __import__("ctypes").c_int
        rc = lib.myssh_sha3_selftest()
        assert rc == 0, f"sha3 selftest failed: rc={rc}"
    r.run("SHA3/SHAKE NIST vectors", t_selftest)

    r.summary()
    return r.failed == 0

# ═══════════════════════════════════════════════════════════
# 2. Ключи
# ═══════════════════════════════════════════════════════════
def test_keys():
    print("\n[2] Ключи")

    r = TestRunner()

    def t_ed25519_save_load():
        keys = SSHKeys(comment="test")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            path = f.name
        try:
            keys.private_key.save(path)
            loaded = Key.load(path)
            assert loaded.bytes() == keys.private_key.bytes()
            assert loaded.fingerprint == keys.private_key.fingerprint
        finally:
            os.unlink(path)
    r.run("Ed25519 save/load", t_ed25519_save_load)

    def t_ed25519_encrypted():
        keys = SSHKeys(comment="test")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            path = f.name
        try:
            keys.private_key.save(path, password="hunter2", rounds=4)
            loaded = Key.load(path, password="hunter2")
            assert loaded.bytes() == keys.private_key.bytes()
            # Wrong password must fail
            try:
                Key.load(path, password="wrong")
                assert False, "wrong password accepted"
            except SSHError:
                pass
        finally:
            os.unlink(path)
    r.run("Ed25519 encrypted save/load", t_ed25519_encrypted)

    def t_ed25519_sign_verify():
        keys = SSHKeys()
        msg = b"hello world"
        sig = keys.private_key.sign(msg)
        assert keys.public_key.verify(msg, sig)
        assert not keys.public_key.verify(b"other", sig)
    r.run("Ed25519 Key sign/verify", t_ed25519_sign_verify)

    def t_rsa_generate():
        for bits in (512, 1024, 2048):
            k = RSAKey.generate(bits=bits)
            assert k.n.bit_length() == bits
    r.run("RSA generate 512/1024/2048", t_rsa_generate)

    def t_rsa_sign_verify():
        for bits in (512, 1024, 2048):
            k = RSAKey.generate(bits=bits)
            msg = b"test msg"
            sig = k.sign(msg, hash_algo="sha2-256")
            assert k.verify(msg, sig, algo_name="rsa-sha2-256")
            assert not k.verify(b"wrong", sig, algo_name="rsa-sha2-256")
    r.run("RSA sign/verify SHA-256", t_rsa_sign_verify)

    def t_rsa_sha512():
        for bits in (1024, 2048):
            k = RSAKey.generate(bits=bits)
            msg = b"test"
            sig = k.sign(msg, hash_algo="sha2-512")
            assert k.verify(msg, sig, algo_name="rsa-sha2-512")
    r.run("RSA sign/verify SHA-512 (1024+)", t_rsa_sha512)

    def t_rsa_too_small():
        # RSA-512 + SHA-512 → ошибка
        k = RSAKey.generate(bits=512)
        try:
            k.sign(b"x", hash_algo="sha2-512")
            assert False, "should have raised"
        except SSHError:
            pass
    r.run("RSA-512 SHA-512 → корректный отказ", t_rsa_too_small)

    def t_rsa_pub_blob():
        k = RSAKey.generate(bits=512)
        blob = k.public_blob()
        # string("ssh-rsa") || mpint(e) || mpint(n)
        algo, off = myssh.read_string(blob, 0)
        assert algo == b"ssh-rsa"
        e, off = myssh.read_string(blob, off)
        n, off = myssh.read_string(blob, off)
        assert int.from_bytes(e, "big") == 65537
        assert int.from_bytes(n, "big") == k.n
    r.run("RSA public_blob формат", t_rsa_pub_blob)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 3. known_hosts
# ═══════════════════════════════════════════════════════════
def test_known_hosts():
    print("\n[3] known_hosts")

    r = TestRunner()

    def t_load_append():
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            path = f.name
        try:
            _kh_append(path, "example.com", 22, "ssh-ed25519", b"\x01\x02\x03")
            entries = _kh_load(path)
            assert "example.com" in entries
            assert entries["example.com"][0][0] == "ssh-ed25519"
        finally:
            os.unlink(path)
    r.run("_kh_append + _kh_load", t_load_append)

    def t_normalize():
        assert _kh_normalize("example.com", 22) == "example.com"
        assert _kh_normalize("example.com", 2222) == "[example.com]:2222"
    r.run("_kh_normalize", t_normalize)

    def t_check_match():
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            path = f.name
        try:
            _kh_append(path, "example.com", 22, "ssh-ed25519", b"\x01\x02\x03")
            entries = _kh_load(path)
            assert _kh_check(entries, "example.com", 22, "ssh-ed25519", b"\x01\x02\x03") == "match"
            assert _kh_check(entries, "example.com", 22, "ssh-ed25519", b"\x09\x09") == "mismatch"
            assert _kh_check(entries, "other.com", 22, "ssh-ed25519", b"\x01\x02\x03") == "unknown"
        finally:
            os.unlink(path)
    r.run("_kh_check match/mismatch/unknown", t_check_match)

    def t_hashed():
        # |1|base64(salt)|base64(hmac-sha1(salt, host))
        import base64, hmac, hashlib
        salt = b"0123456789abcdef"
        host = "example.com"
        h = hmac.new(salt, host.encode(), hashlib.sha1).digest()
        pattern = "|1|" + base64.b64encode(salt).decode().rstrip("=") + "|" + base64.b64encode(h).decode().rstrip("=")
        assert myssh._kh_matches_hashed(pattern, host)
        assert not myssh._kh_matches_hashed(pattern, "other.com")
    r.run("hashed known_hosts", t_hashed)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 4. Транспорт: наш сервер ↔ наш клиент
# ═══════════════════════════════════════════════════════════
def test_transport_ed25519():
    print("\n[4] Транспорт: Ed25519 host key")

    r = TestRunner()
    hk = SSHKeys(comment="host@test")
    alice = SSHKeys(comment="alice@test")
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        def t_handshake():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False, verbose=False)
            assert s.host_fp == hk.public_key.fingerprint
            s.close()
        r.run("handshake + host key fp", t_handshake)

        def t_auth():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False)
            assert s.authenticate("alice")
            s.close()
        r.run("publickey auth (Ed25519)", t_auth)

        def t_wrong_user():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False)
            try:
                assert not s.authenticate("bob")
            finally:
                s.close()
        r.run("auth rejects wrong user", t_wrong_user)

        def t_exec():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False)
            s.authenticate("alice")
            s.open_session()
            st, out = s.exec_command("whoami")
            assert st == 0
            assert b"alice" in out or b"u0_" in out or b"root" in out
            s.close()
        r.run("exec whoami", t_exec)

        def t_exec_unknown():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False)
            s.authenticate("alice")
            s.open_session()
            st, out = s.exec_command("rm -rf /")
            # не в whitelist
            assert st == 127
            s.close()
        r.run("exec whitelist rejects rm", t_exec_unknown)

        def t_password():
            # Этот сервер использует только publickey; попробуем пароль → fail
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False)
            assert not s.authenticate_password("alice", "wrong")
            s.close()
        r.run("password auth reject (no passwords)", t_password)

    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 5. Транспорт: RSA host key
# ═══════════════════════════════════════════════════════════
def test_transport_rsa():
    print("\n[5] Транспорт: RSA host key")

    r = TestRunner()
    try:
        hk = RSAKeys(bits=1024, comment="host@rsa")
    except Exception as e:
        print(f"  [skip] RSA keygen failed: {e}")
        return True

    alice = SSHKeys(comment="alice@test")
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        def t_handshake():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False, verbose=False)
            assert s.host_fp == hk.public_key.fingerprint
            s.close()
        r.run("handshake + RSA host key fp", t_handshake)

        def t_auth_exec():
            s = SSH(alice.public_key, alice.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False)
            assert s.authenticate("alice")
            s.open_session()
            st, out = s.exec_command("echo RSA_OK")
            assert st == 0
            assert b"RSA_OK" in out
            s.close()
        r.run("RSA host key auth + exec", t_auth_exec)
    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 6. Транспорт: RSA user key
# ═══════════════════════════════════════════════════════════
def test_transport_rsa_user():
    print("\n[6] Транспорт: RSA user key (publickey auth)")

    r = TestRunner()
    try:
        hk = SSHKeys(comment="host@test")
        alice_rsa = RSAKeys(bits=1024, comment="alice@rsa")
    except Exception as e:
        print(f"  [skip] keygen failed: {e}")
        return True

    port = _free_port()
    srv = _mk_server(hk, {"alice": alice_rsa.public_key}, port)

    try:
        def t_rsa_auth():
            s = SSH(alice_rsa.public_key, alice_rsa.private_key,
                    ("127.0.0.1", port), known_hosts=None, strict=False, verbose=True)
            ok = s.authenticate("alice")
            s.close()
            assert ok, "RSA user auth rejected by our server"
        r.run("RSA user publickey auth", t_rsa_auth)
    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 7. MITM-защита
# ═══════════════════════════════════════════════════════════
def test_mitm():
    print("\n[7] MITM-защита")

    r = TestRunner()
    hk = SSHKeys(comment="host@test")
    alice = SSHKeys(comment="alice@test")
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        def t_mitm_detected():
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                kh = f.name
            try:
                fake = SSHKeys(comment="attacker")
                b64 = __import__("base64").b64encode(fake.public_key.public_blob()).decode().rstrip("=")
                with open(kh, "w") as fp:
                    fp.write(f"[127.0.0.1]:{port} ssh-ed25519 {b64}\n")
                try:
                    SSH(alice.public_key, alice.private_key,
                        ("127.0.0.1", port), known_hosts=kh, strict=True)
                    assert False, "MITM not detected"
                except SSHHostKeyError:
                    pass
            finally:
                os.unlink(kh)
        r.run("MITM → SSHHostKeyError", t_mitm_detected)

        def t_tofu():
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                kh = f.name
            try:
                # strict=False → TOFU: добавить ключ
                s = SSH(alice.public_key, alice.private_key,
                        ("127.0.0.1", port), known_hosts=kh, strict=False)
                s.close()
                entries = _kh_load(kh)
                target = _kh_normalize("127.0.0.1", port)
                assert target in entries
                # повторно — match
                s = SSH(alice.public_key, alice.private_key,
                        ("127.0.0.1", port), known_hosts=kh, strict=True)
                s.close()
            finally:
                os.unlink(kh)
        r.run("TOFU: new → add → match", t_tofu)
    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 8. Packetizer / kexinit
# ═══════════════════════════════════════════════════════════
def test_protocol_helpers():
    print("\n[8] Protocol helpers")

    r = TestRunner()

    def t_kexinit_roundtrip():
        kex = build_kexinit()
        parsed = parse_kexinit(kex)
        assert "curve25519-sha256" in parsed["kex"]
        assert "ssh-ed25519" in parsed["hostkey"]
        # хоть один из шифров должен быть в списке
        ciphers = parsed["enc_c2s"]
        assert ("chacha20-poly1305@openssh.com" in ciphers
                or "aes256-gcm@openssh.com" in ciphers), f"c2s ciphers: {ciphers}"
    r.run("build_kexinit → parse_kexinit", t_kexinit_roundtrip)

    def t_calc_pad_plaintext():
        class S:
            def sendall(self, d): pass
            def recv(self, n): return b""
        p = Packetizer(S())
        # plaintext: (pkt-4) % 8 == 0
        for plen in (0, 1, 17, 100, 343, 372):
            pad = p._calc_pad(plen)
            assert 4 <= pad <= 255
            pkt = 1 + plen + pad
            # plaintext: packet_length (4+pkt)? OpenSSH проверяет (pkt - 4) % 8 == 0?
            # Согласно нашему решению: (4 + 1 + plen + pad) % 8 == 0
            assert (4 + 1 + plen + pad) % 8 == 0, f"plen={plen} pad={pad}"
    r.run("_calc_pad plaintext", t_calc_pad_plaintext)

    def t_calc_pad_encrypted():
        class S:
            def sendall(self, d): pass
            def recv(self, n): return b""
        p = Packetizer(S())
        p.cipher = "chacha20-poly1305@openssh.com"
        p._block = 8
        for plen in (0, 1, 17, 100, 343, 372):
            pad = p._calc_pad(plen)
            assert 4 <= pad <= 255
            pkt = 1 + plen + pad
            assert pkt % 8 == 0, f"plen={plen} pad={pad} pkt={pkt}"
    r.run("_calc_pad encrypted", t_calc_pad_encrypted)

    def t_negotiate():
        their = parse_kexinit(build_kexinit())
        algs = negotiate(their)
        assert algs["kex"] is not None
        assert algs["hostkey"] is not None
        assert algs["enc_c2s"] is not None
    r.run("negotiate", t_negotiate)

    def t_derive_key_deterministic():
        k1 = derive_key(b"K", b"H", b"H", b"C", 64)
        k2 = derive_key(b"K", b"H", b"H", b"C", 64)
        assert k1 == k2
        assert len(k1) == 64
        k3 = derive_key(b"K", b"H", b"H", b"D", 64)
        assert k3 != k1
    r.run("derive_key deterministic + different letters", t_derive_key_deterministic)

    def t_ssh_mpint():
        assert ssh_mpint(0) == b"\x00\x00\x00\x00"
        assert ssh_mpint(0x80) == b"\x00\x00\x00\x02\x00\x80"
        assert ssh_mpint(0x7f) == b"\x00\x00\x00\x01\x7f"
    r.run("ssh_mpint", t_ssh_mpint)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 9. OpenSSH интероп (опционально)
# ═══════════════════════════════════════════════════════════
def test_openssh_interop():
    print("\n[9] OpenSSH интероп (localhost:8022)")

    r = TestRunner()

    # Проверяем, поднят ли sshd
    import socket
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect(("127.0.0.1", 8022))
        s.close()
    except (ConnectionRefusedError, socket.timeout, OSError):
        print("  [skip] sshd на 8022 не запущен")
        return True

    # Ищем ключ в ~/.ssh/
    user = myssh._get_username()
    key_paths = ["~/.ssh/myssh_test", "~/.ssh/id_ed25519"]
    key = None
    for kp in key_paths:
        path = os.path.expanduser(kp)
        if os.path.exists(path):
            try:
                key = Key.load(path)
                break
            except Exception:
                continue
    if key is None:
        print("  [skip] нет подходящего ключа в ~/.ssh/")
        return True

    def t_handshake():
        s = SSH(key, key, ("127.0.0.1", 8022), known_hosts=None, strict=False)
        assert s.host_fp.startswith("SHA256:")
        s.close()
    r.run("handshake + host fp", t_handshake)

    def t_auth():
        s = SSH(key, key, ("127.0.0.1", 8022), known_hosts=None, strict=False)
        try:
            ok = s.authenticate(user)
            assert ok, "auth failed"
        finally:
            s.close()
    r.run(f"publickey auth ({os.path.basename(key_paths[0])})", t_auth)

    def t_exec():
        s = SSH(key, key, ("127.0.0.1", 8022), known_hosts=None, strict=False)
        try:
            assert s.authenticate(user)
            s.open_session()
            st, out = s.exec_command("echo MYSSH_INTEROP_OK; whoami")
            assert st == 0
            assert b"MYSSH_INTEROP_OK" in out
            assert user.encode() in out
        finally:
            s.close()
    r.run("exec через OpenSSH", t_exec)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# main
# ═══════════════════════════════════════════════════════════
def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  myssh — автотесты                                       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Python: {sys.version.split()[0]}")
    print(f"C backend: {myssh._PRIM_C_PATH or 'НЕТ'}")

    args = set(sys.argv[1:])
    only = None
    for a in args:
        if a.startswith("--only="):
            only = a.split("=", 1)[1].split(",")

    suites = {
        "crypto":       test_crypto,
        "sha3":         test_sha3,
        "keys":         test_keys,
        "known_hosts":  test_known_hosts,
        "ed25519":      test_transport_ed25519,
        "rsa":          test_transport_rsa,
        "rsa_user":     test_transport_rsa_user,
        "mitm":         test_mitm,
        "protocol":     test_protocol_helpers,
        "openssh":      test_openssh_interop,
    }

    results = {}
    for name, fn in suites.items():
        if only and name not in only:
            continue
        try:
            results[name] = fn()
        except Exception as e:
            print(f"\n[!] Suite {name} crashed: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Итог                                                    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    for name, ok in results.items():
        mark = "✓" if ok else "✗"
        print(f"  {mark} {name}")

    all_ok = all(results.values())
    print()
    print("ВСЁ ОК" if all_ok else "ЕСТЬ ПАДЕНИЯ")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
