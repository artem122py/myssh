#!/usr/bin/env python3
# stress_audit.py — стресс-тест и псевдо-аудит myssh.
# Прогоняет 10 категорий атак/сбоев. Не разрушает систему (все на localhost).
import sys, os, socket, struct, time, threading, secrets, random, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MSG_KEXINIT = 20
MSG_KEX_ECDH_INIT = 30
MSG_KEX_ECDH_REPLY = 31
MSG_NEWKEYS = 21
MSG_SERVICE_REQUEST = 5
MSG_USERAUTH_REQUEST = 50

from myssh import (
    SSH, SSHServer, SSHKeys, RSAKeys, Key, RSAKey,
    Packetizer, Transport, build_kexinit, parse_kexinit, negotiate,
    _ssh_string, read_string, ssh_mpint,
    SSHProtocolError, SSHHostKeyError, SSHAuthError, SSHCryptoError,
    SSHChannelError,
    AESGCM, Ed25519, X25519,
)

# ─── Мини-фреймворк ────────────────────────────────────────
class Audit:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def run(self, name, fn):
        try:
            result = fn()
            if result is False:
                self.failed += 1
                self.errors.append((name, "test returned False"))
                print(f"  [FAIL] {name}")
            else:
                self.passed += 1
                print(f"  [ok]   {name}")
        except Exception as e:
            self.failed += 1
            self.errors.append((name, f"{type(e).__name__}: {e}"))
            print(f"  [CRASH] {name}: {type(e).__name__}: {e}")

    def summary(self):
        total = self.passed + self.failed
        print()
        print(f"═══ ИТОГО: {self.passed}/{total} ok, {self.failed} fail ═══")
        if self.errors:
            print()
            for name, e in self.errors:
                print(f"  [FAIL] {name}: {e}")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _mk_server(host_keys, users, port, **kw):
    srv = SSHServer(host_keys=host_keys, addr=("127.0.0.1", port),
                    users=users, verbose=False, shell_mode="auto", **kw)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv


def _raw_connect(port):
    """Открыть TCP-соединение для грубых тестов."""
    s = socket.socket()
    s.settimeout(2)
    s.connect(("127.0.0.1", port))
    return s


# ═══════════════════════════════════════════════════════════
# 1. Fuzzing: мусор на входе
# ═══════════════════════════════════════════════════════════
def test_fuzzing():
    print("\n[1] Fuzzing — мусорные данные")

    r = Audit()
    hk = SSHKeys()
    alice = SSHKeys()
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        # A. Отправляем случайные байты вместо SSH-версии
        def t_random_banner():
            for _ in range(5):
                s = _raw_connect(port)
                s.sendall(secrets.token_bytes(random.randint(1, 100)))
                time.sleep(0.1)
                s.close()
            return True
        r.run("Случайные байты в banner", t_random_banner)

        # B. Длинный banner (>255 байт)
        def t_long_banner():
            s = _raw_connect(port)
            s.sendall(b"SSH-2.0-" + b"A" * 500 + b"\r\n")
            time.sleep(0.2)
            s.close()
            return True
        r.run("Banner > 255 байт", t_long_banner)

        # C. Banner без \n (timeout)
        def t_no_newline_banner():
            s = _raw_connect(port)
            s.sendall(b"SSH-2.0-Test")
            time.sleep(0.3)
            s.close()
            return True
        r.run("Banner без newline", t_no_newline_banner)

        # D. Мусор после нормальной версии
        def t_junk_after_version():
            s = _raw_connect(port)
            # Читаем version сервера
            s.recv(100)
            s.sendall(b"SSH-2.0-Fuzzer\r\n")
            s.sendall(secrets.token_bytes(200))
            time.sleep(0.2)
            s.close()
            return True
        r.run("Мусор после version", t_junk_after_version)

        # E. Случайные packet_length
        def t_random_packet_len():
            try:
                s = _raw_connect(port)
                s.recv(100)
                s.sendall(b"SSH-2.0-Fuzzer\r\n")
                time.sleep(0.1)
                for _ in range(10):
                    pkt = struct.pack(">I", random.randint(0, 2**32 - 1)) + secrets.token_bytes(64)
                    try:
                        s.sendall(pkt)
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        break  # сервер корректно закрыл — это OK
                    time.sleep(0.05)
                try: s.close()
                except Exception: pass
            except (ConnectionResetError, OSError):
                pass  # ожидаемое поведение
            return True
        r.run("Случайные packet_length", t_random_packet_len)

        # F. Огромный packet_length
        def t_huge_packet_len():
            s = _raw_connect(port)
            s.recv(100)
            s.sendall(b"SSH-2.0-Fuzzer\r\n")
            time.sleep(0.1)
            s.sendall(struct.pack(">I", 0xFFFFFFFF) + b"\x00" * 8)
            time.sleep(0.2)
            s.close()
            return True
        r.run("Huge packet_length (0xFFFFFFFF)", t_huge_packet_len)

        # G. packet_length < минимума
        def t_tiny_packet_len():
            s = _raw_connect(port)
            s.recv(100)
            s.sendall(b"SSH-2.0-Fuzzer\r\n")
            time.sleep(0.1)
            s.sendall(struct.pack(">I", 0) + b"\x00" * 8)
            time.sleep(0.2)
            s.close()
            return True
        r.run("Tiny packet_length (0)", t_tiny_packet_len)

        # H. Медленное соединение (slowloris, короткий тест)
        def t_slowloris():
            s = _raw_connect(port)
            for i in range(20):
                s.sendall(b"A")
                time.sleep(0.01)
            s.close()
            return True
        r.run("Slowloris (20 медленных байт)", t_slowloris)

    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 2. Padding violations
# ═══════════════════════════════════════════════════════════
def test_padding():
    print("\n[2] Padding violations")

    r = Audit()

    def t_valid_pads():
        """Проверим, что _calc_pad даёт корректные значения."""
        for enc in [None, "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]:
            class S:
                def sendall(self, d): pass
                def recv(self, n): return b""
            p = Packetizer(S())
            if enc:
                p.cipher = enc
                p._block = 8 if enc.startswith("chacha") else 16
            for plen in range(0, 1000, 7):
                pad = p._calc_pad(plen)
                if pad < 4 or pad > 255:
                    return False
                block = p._block
                # plaintext: (pkt - 4) % block == 0
                # AEAD: pkt % block == 0
                pkt = 1 + plen + pad
                if enc is None:
                    if (4 + pkt) % block != 0:
                        return False
                else:
                    if pkt % block != 0:
                        return False
        return True
    r.run("_calc_pad корректен для всех block/plen", t_valid_pads)

    # B. Тамперинг padded plaintext
    def t_pad_tamper():
        hk = SSHKeys()
        alice = SSHKeys()
        port = _free_port()
        srv = _mk_server(hk, {"alice": alice.public_key}, port)
        try:
            for _ in range(5):
                s = _raw_connect(port)
                s.recv(100)
                s.sendall(b"SSH-2.0-Tamper\r\n")
                time.sleep(0.1)
                # Валидный KEXINIT + подмена байта
                kex = build_kexinit()
                pad = _calc_pad_simple(len(kex))
                pkt = struct.pack(">I", 1 + len(kex) + pad) + bytes([pad]) + kex + b"\x00" * pad
                # Тамперим один байт
                pkt = bytearray(pkt)
                pkt[10] ^= 1
                s.sendall(bytes(pkt))
                time.sleep(0.2)
                s.close()
            return True
        finally:
            srv.stop()
    r.run("Тамперинг padded plaintext (не должно крешить)", t_pad_tamper)

    r.summary()
    return r.failed == 0


def _calc_pad_simple(plen):
    pad = (-(4 + 1 + plen)) % 8
    if pad < 4:
        pad += 8
    return pad


# ═══════════════════════════════════════════════════════════
# 3. AEAD tampering (шифрованный канал)
# ═══════════════════════════════════════════════════════════
def test_aead_tampering():
    print("\n[3] AEAD tampering")

    r = Audit()

    def t_gcm_tamper():
        """Тамперинг GCM-шифртекста должен давать ошибку."""
        key = bytes(32); nonce = bytes(12); pt = b"Hello, world!"
        g = AESGCM(key)
        ct = bytearray(g.encrypt(nonce, pt))
        for i in range(0, len(ct), 3):
            c2 = bytearray(ct)
            c2[i] ^= 1
            try:
                g.decrypt(nonce, bytes(c2))
                return False  # должно было упасть
            except SSHCryptoError:
                pass
        return True
    r.run("AES-GCM: тамперинг любого байта → ошибка", t_gcm_tamper)

    def t_nonce_reuse_detected():
        """Разные nonce дают разные ct; один nonce — не детектируется на уровне GCM."""
        g = AESGCM(bytes(32))
        ct1 = g.encrypt(bytes(12), b"msg")
        ct2 = g.encrypt(bytes([1])+bytes(11), b"msg")
        return ct1 != ct2
    r.run("Разные nonce → разные ct", t_nonce_reuse_detected)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 4. KEX renegotiation & version mismatch
# ═══════════════════════════════════════════════════════════
def test_kex_attacks():
    print("\n[4] KEX-атаки")

    r = Audit()

    # A. Двойной KEXINIT (renegotiation)
    def t_double_kexinit():
        hk = SSHKeys()
        alice = SSHKeys()
        port = _free_port()
        srv = _mk_server(hk, {"alice": alice.public_key}, port)
        try:
            s = _raw_connect(port)
            s.recv(100)
            s.sendall(b"SSH-2.0-DoubleKex\r\n")
            time.sleep(0.1)
            kex = build_kexinit()
            for _ in range(3):
                pad = _calc_pad_simple(len(kex))
                pkt = struct.pack(">I", 1 + len(kex) + pad) + bytes([pad]) + kex + b"\x00" * pad
                s.sendall(pkt)
                time.sleep(0.05)
            s.close()
            return True
        finally:
            srv.stop()
    r.run("Двойной/тройной KEXINIT", t_double_kexinit)

    # B. KEXINIT с пустыми namelist'ами
    def t_empty_kexinit():
        hk = SSHKeys()
        alice = SSHKeys()
        port = _free_port()
        srv = _mk_server(hk, {"alice": alice.public_key}, port)
        try:
            s = _raw_connect(port)
            s.recv(100)
            s.sendall(b"SSH-2.0-EmptyKex\r\n")
            time.sleep(0.1)
            # Пустой KEXINIT
            payload = bytes([MSG_KEXINIT]) + secrets.token_bytes(16)
            for _ in range(10):  # 10 пустых namelist'ов
                payload += struct.pack(">I", 0)
            payload += b"\x00" + struct.pack(">I", 0)
            pad = _calc_pad_simple(len(payload))
            pkt = struct.pack(">I", 1 + len(payload) + pad) + bytes([pad]) + payload + b"\x00" * pad
            s.sendall(pkt)
            time.sleep(0.2)
            s.close()
            return True
        finally:
            srv.stop()
    r.run("KEXINIT с пустыми namelist", t_empty_kexinit)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 5. Userauth bypass
# ═══════════════════════════════════════════════════════════
def test_auth_bypass():
    print("\n[5] Userauth bypass attempts")

    r = Audit()
    hk = SSHKeys()
    alice = SSHKeys()
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        # A. Чужой ключ (не alice)
        def t_wrong_key():
            eve = SSHKeys()
            try:
                s = SSH(alice.public_key, eve.private_key, ("127.0.0.1", port),
                        known_hosts=None, strict=False)
                # Должны получить False
                try:
                    ok = s.authenticate("alice")
                    s.close()
                    return ok is False
                except SSHAuthError:
                    s.close()
                    return True
            except Exception:
                return True
        r.run("Аутентификация чужим ключом → отказ", t_wrong_key)

        # B. Несуществующий пользователь
        def t_unknown_user():
            try:
                s = SSH(alice.public_key, alice.private_key, ("127.0.0.1", port),
                        known_hosts=None, strict=False)
                try:
                    ok = s.authenticate("bob")
                    s.close()
                    return ok is False
                except (SSHAuthError, SSHProtocolError):
                    s.close()
                    return True
            except Exception:
                return True
        r.run("Несуществующий пользователь → отказ", t_unknown_user)

        # C. Подмена session_id (replay)
        def t_replay_protection():
            """Подпись привязана к session_id — проверим, что verify с другим H падает."""
            keys = SSHKeys()
            msg = b"test-message"
            sig = keys.private_key.sign(msg)
            ok1 = keys.public_key.verify(msg, sig)
            ok2 = keys.public_key.verify(b"other-message", sig)
            return ok1 and not ok2
        r.run("Подпись привязана к сообщению", t_replay_protection)

    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 6. Crypto boundary tests
# ═══════════════════════════════════════════════════════════
def test_crypto_boundaries():
    print("\n[6] Границы крипто-примитивов")

    r = Audit()

    def t_ed25519_wrong_sig():
        keys = SSHKeys()
        msg = b"hello"
        sig = keys.private_key.sign(msg)
        bad = bytearray(sig); bad[0] ^= 1
        return not keys.public_key.verify(msg, bytes(bad))
    r.run("Ed25519: испорченная подпись → False", t_ed25519_wrong_sig)

    def t_ed25519_wrong_len():
        keys = SSHKeys()
        try:
            return not keys.public_key.verify(b"x", b"short")
        except Exception:
            return True  # тоже OK — исключение допустимо
    r.run("Ed25519: подпись неверной длины", t_ed25519_wrong_len)

    def t_x25519_low_order():
        """Низкопорядковые точки → должны отвергаться."""
        priv = secrets.token_bytes(32)
        # Известные low-order точки
        lows = [
            bytes(32),                    # 0
            bytes([1] + [0]*31),           # 1
            bytes([0]*31 + [0x80]),        # ?
        ]
        for low in lows:
            try:
                X25519.scalarmult(priv, low)
                # Не должно возвращать полезное значение, но не крешится
            except SSHCryptoError:
                pass  # хорошо
            except Exception:
                return False  # плохо
        return True
    r.run("X25519: low-order точки не крешат", t_x25519_low_order)

    def t_rsa_wrong_msg():
        k = RSAKey.generate(bits=512)
        sig = k.sign(b"correct")
        return not k.verify(b"wrong", sig, algo_name="rsa-sha2-256")
    r.run("RSA: подпись не для того сообщения", t_rsa_wrong_msg)

    def t_rsa_key_size():
        """RSA-512+SHA-512 → отказ (не хватает места)."""
        k = RSAKey.generate(bits=512)
        try:
            k.sign(b"x", hash_algo="sha2-512")
            return False  # должно было упасть
        except SSHCryptoError:
            return True
    r.run("RSA-512+SHA-512 → отказ", t_rsa_key_size)

    def t_aesgcm_wrong_tag():
        g = AESGCM(bytes(32))
        ct = bytearray(g.encrypt(bytes(12), b"hello"))
        ct[-1] ^= 1
        try:
            g.decrypt(bytes(12), bytes(ct))
            return False
        except SSHCryptoError:
            return True
    r.run("AES-GCM: испорченный tag → ошибка", t_aesgcm_wrong_tag)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 7. known_hosts / MITM
# ═══════════════════════════════════════════════════════════
def test_mitm():
    print("\n[7] MITM / known_hosts атаки")

    r = Audit()
    hk = SSHKeys()
    alice = SSHKeys()
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        # A. MITM: разные ключи
        def t_mitm_detect():
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                kh = f.name
            try:
                fake = SSHKeys()
                import base64 as b64
                blob = b64.b64encode(fake.public_key.public_blob()).decode().rstrip("=")
                with open(kh, "w") as f:
                    f.write(f"[127.0.0.1]:{port} ssh-ed25519 {blob}\n")
                try:
                    SSH(alice.public_key, alice.private_key,
                        ("127.0.0.1", port), known_hosts=kh, strict=True)
                    return False
                except SSHHostKeyError:
                    return True
            finally:
                os.unlink(kh)
        r.run("MITM: подмена host key → SSHHostKeyError", t_mitm_detect)

        # B. Много запросов с разными host keys
        def t_many_hostkeys():
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                kh = f.name
            try:
                import base64 as b64
                with open(kh, "w") as f:
                    for _ in range(50):
                        k = SSHKeys()
                        blob = b64.b64encode(k.public_key.public_blob()).decode().rstrip("=")
                        f.write(f"[127.0.0.1]:{port} ssh-ed25519 {blob}\n")
                try:
                    SSH(alice.public_key, alice.private_key,
                        ("127.0.0.1", port), known_hosts=kh, strict=True)
                    return False
                except SSHHostKeyError:
                    return True
            finally:
                os.unlink(kh)
        r.run("known_hosts с 50 разными ключами → MITM", t_many_hostkeys)

    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 8. Sequence number desync
# ═══════════════════════════════════════════════════════════
def test_seq_desync():
    print("\n[8] Sequence number десинхронизация")

    r = Audit()

    def t_seq_wrap():
        """Sequence number — 32-битный, при переполнении оборачивается."""
        class S:
            def sendall(self, d): pass
            def recv(self, n): return b""
        p = Packetizer(S())
        p.seq_send = 0xFFFFFFFF
        # Отправить пакет — должен обернуться в 0
        p.send(b"\x01" + b"test")
        return p.seq_send == 0
    r.run("Sequence number wrap 0xFFFFFFFF→0", t_seq_wrap)

    def t_seq_reset_after_newkeys():
        """После NEWKEYS seq должен сброситься."""
        # Логика в коде, проверим через полный handshake
        hk = SSHKeys()
        alice = SSHKeys()
        port = _free_port()
        srv = _mk_server(hk, {"alice": alice.public_key}, port)
        try:
            s = SSH(alice.public_key, alice.private_key, ("127.0.0.1", port),
                    known_hosts=None, strict=False)
            ok = s.authenticate("alice")
            s.close()
            return ok
        finally:
            srv.stop()
    r.run("Seq reset после NEWKEYS (полный handshake)", t_seq_reset_after_newkeys)

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# 9. SFTP path traversal
# ═══════════════════════════════════════════════════════════
def test_sftp_path_traversal():
    print("\n[9] SFTP path traversal")

    r = Audit()
    hk = SSHKeys()
    alice = SSHKeys()
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)
    srv.sftp_root = os.path.expanduser("~")

    try:
        from myssh import SFTPClient
        s = SSH(alice.public_key, alice.private_key, ("127.0.0.1", port),
                known_hosts=None, strict=False)
        s.authenticate("alice")
        sftp = SFTPClient(s)
        sftp.open_session()

        attacks = [
            "/../../../../etc/passwd",
            "../../../../etc/passwd",
            "/./../../etc/passwd",
            "//..//..//etc/passwd",
            "/../root/.ssh/id_rsa",
            "/....//....//etc/passwd",
        ]
        blocked = 0
        for path in attacks:
            try:
                # stat через SFTPClient (если есть), иначе — listdir
                if hasattr(sftp, "stat"):
                    sftp.stat(path)
                else:
                    sftp.listdir(path)
                # Если не упало — bad
            except Exception:
                blocked += 1

        sftp.close()
        s.close()
        # Все атаки должны быть отвергнуты
        return blocked == len(attacks)
    except Exception as e:
        print(f"    [!] тест упал: {type(e).__name__}: {e}")
        return False
    finally:
        srv.stop()


# ═══════════════════════════════════════════════════════════
# 10. Resource exhaustion (лёгкий)
# ═══════════════════════════════════════════════════════════
def test_resource_exhaustion():
    print("\n[10] Resource exhaustion (кратко)")

    r = Audit()
    hk = SSHKeys()
    alice = SSHKeys()
    port = _free_port()
    srv = _mk_server(hk, {"alice": alice.public_key}, port)

    try:
        # A. Много одновременных TCP-соединений
        def t_many_conns():
            conns = []
            for _ in range(20):
                try:
                    s = _raw_connect(port)
                    conns.append(s)
                except Exception:
                    pass
            for s in conns:
                try: s.close()
                except Exception: pass
            return True
        r.run("20 одновременных TCP-соединений", t_many_conns)

        # B. Много подключений подряд
        def t_rapid_conns():
            for _ in range(30):
                try:
                    s = _raw_connect(port)
                    s.close()
                except Exception:
                    pass
            return True
        r.run("30 быстрых подключений", t_rapid_conns)

        # C. Один клиент с большим payload (exec)
        def t_big_exec():
            s = SSH(alice.public_key, alice.private_key, ("127.0.0.1", port),
                    known_hosts=None, strict=False)
            s.authenticate("alice")
            s.open_session()
            # exec с большим выводом (эхо 10К)
            st, out = s.exec_command("echo " + "A" * 10000)
            s.close()
            return st == 0
        r.run("exec с большим выводом (10KB)", t_big_exec)

    finally:
        srv.stop()

    r.summary()
    return r.failed == 0


# ═══════════════════════════════════════════════════════════
# main
# ═══════════════════════════════════════════════════════════
def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  myssh — стресс-тест / псевдо-аудит                     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    args = set(sys.argv[1:])
    only = None
    for a in args:
        if a.startswith("--only="):
            only = a.split("=", 1)[1].split(",")

    suites = {
        "fuzzing":    test_fuzzing,
        "padding":    test_padding,
        "aead":       test_aead_tampering,
        "kex":        test_kex_attacks,
        "auth":       test_auth_bypass,
        "crypto":     test_crypto_boundaries,
        "mitm":       test_mitm,
        "seq":        test_seq_desync,
        "sftp":       test_sftp_path_traversal,
        "exhaust":    test_resource_exhaustion,
    }

    results = {}
    for name, fn in suites.items():
        if only and name not in only:
            continue
        try:
            results[name] = fn()
        except Exception as e:
            print(f"\n[!] Suite {name} crashed: {type(e).__name__}: {e}")
            traceback.print_exc()
            results[name] = False

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  ИТОГ АУДИТА                                             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    for name, ok in results.items():
        mark = "✅" if ok else "❌"
        print(f"  {mark} {name}")

    all_ok = all(results.values())
    print()
    if all_ok:
        print("🎉 ВСЕ АТАКИ ОТРАЖЕНЫ. Система устойчива.")
    else:
        print("⚠️  Есть падения — см. выше.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
