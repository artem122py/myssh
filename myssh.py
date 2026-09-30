# myssh.py — свой SSH на чистом Python. pty + pipe shell, heredoc, logout.
# Только stdlib.

import base64, hashlib, hmac, os, re, secrets, select, socket, struct
import subprocess, sys, threading, time, shlex

# ═══════════════════════════════════════════════════════════════════════
# 1. Ed25519 (RFC 8032) — своя, hardened
# ═══════════════════════════════════════════════════════════════════════
_L = 2**252 + 27742317777372353535851937790883648493


# ═══════════════════════════════════════════════════════════════════════
# Крипто-примитивы. Все реализации — на C (libmyssh.so).
# Python-код — только тонкие обёртки для вызова C через ctypes.
# ═══════════════════════════════════════════════════════════════════════

class X25519:
    """X25519 (RFC 7748). Обёртка над C-реализацией."""
    @staticmethod
    def clamp(k):
        k = bytearray(k)
        k[0] &= 248; k[31] &= 127; k[31] |= 64
        return bytes(k)

    @classmethod
    def scalarmult_base(cls, s):
        import ctypes as _ct
        if len(s) != 32: raise SSHCryptoError("scalar must be 32 bytes")
        _U8 = _ct.c_ubyte
        kb = (_U8 * 32).from_buffer_copy(s)
        ob = (_U8 * 32)()
        rc = _PRIM_C.myssh_x25519_scalarmult_base(kb, ob)
        if rc != 0: raise SSHCryptoError("x25519_scalarmult_base failed")
        return bytes(ob)

    @classmethod
    def scalarmult(cls, s, point):
        import ctypes as _ct
        if len(s) != 32 or len(point) != 32:
            raise ValueError("arguments must be 32 bytes")
        _U8 = _ct.c_ubyte
        kb = (_U8 * 32).from_buffer_copy(s)
        pb = (_U8 * 32).from_buffer_copy(point)
        ob = (_U8 * 32)()
        rc = _PRIM_C.myssh_x25519_scalarmult(kb, pb, ob)
        if rc != 0: raise SSHCryptoError("X25519: low-order point")
        return bytes(ob)




# ═══════════════════════════════════════════════════════════════════════
# ML-KEM-768 (FIPS 203) — обёртка над libmyssh.so
# ═══════════════════════════════════════════════════════════════════════
class MLKEM768:
    """ML-KEM-768 (FIPS 203). Обёртка над C-реализацией."""
    PUBLICKEYBYTES  = 1184
    SECRETKEYBYTES  = 2400
    CIPHERTEXTBYTES = 1088
    SSBYTES         = 32
    KEYGEN_COINS    = 64
    ENCAPS_COINS    = 32

    @staticmethod
    def keygen(coins=None):
        """Возвращает (ek, dk) — public (1184) и secret (2400)."""
        import ctypes as _ct, secrets as _s
        if coins is None:
            coins = _s.token_bytes(64)
        if len(coins) != 64:
            raise ValueError("coins must be 64 bytes")
        U8 = _ct.c_ubyte
        cbuf = (U8 * 64).from_buffer_copy(coins)
        ek = (U8 * 1184)()
        dk = (U8 * 2400)()
        rc = _PRIM_C.myssh_mlkem768_keygen(ek, dk, cbuf)
        if rc != 0:
            raise SSHCryptoError(f"mlkem768_keygen failed: rc={rc}")
        return bytes(ek), bytes(dk)

    @staticmethod
    def encaps(ek, coins=None):
        """Возвращает (ss, ct) — shared secret (32) и ciphertext (1088)."""
        import ctypes as _ct, secrets as _s
        if coins is None:
            coins = _s.token_bytes(32)
        if len(coins) != 32:
            raise ValueError("coins must be 32 bytes")
        if len(ek) != 1184:
            raise ValueError("ek must be 1184 bytes")
        U8 = _ct.c_ubyte
        ekbuf = (U8 * 1184).from_buffer_copy(ek)
        cbuf  = (U8 * 32).from_buffer_copy(coins)
        ss = (U8 * 32)()
        ct = (U8 * 1088)()
        rc = _PRIM_C.myssh_mlkem768_encaps(ss, ct, ekbuf, cbuf)
        if rc != 0:
            raise SSHCryptoError(f"mlkem768_encaps failed: rc={rc}")
        return bytes(ss), bytes(ct)

    @staticmethod
    def decaps(ct, dk):
        """Возвращает ss (32)."""
        import ctypes as _ct
        if len(ct) != 1088:
            raise ValueError("ct must be 1088 bytes")
        if len(dk) != 2400:
            raise ValueError("dk must be 2400 bytes")
        U8 = _ct.c_ubyte
        ctbuf = (U8 * 1088).from_buffer_copy(ct)
        dkbuf = (U8 * 2400).from_buffer_copy(dk)
        ss = (U8 * 32)()
        rc = _PRIM_C.myssh_mlkem768_decaps(ss, ctbuf, dkbuf)
        if rc != 0:
            raise SSHCryptoError(f"mlkem768_decaps failed: rc={rc}")
        return bytes(ss)


# ═══════════════════════════════════════════════════════════════════════
# Big-endian increment (для GCM nonce / counter block)
# ═══════════════════════════════════════════════════════════════════════
def _be_inc(buf, start=0):
    """Инкремент buf[start:] как big-endian числа, in-place.
    Возвращает False при полном wrap, True иначе."""
    for i in range(len(buf) - 1, start - 1, -1):
        buf[i] = (buf[i] + 1) & 0xFF
        if buf[i] != 0:
            return True
    return False

class AESGCM:
    """AES-256-GCM (NIST SP 800-38D). Обёртка над C-реализацией.
    Совместим с cryptography.hazmat.primitives.ciphers.aead.AESGCM."""
    def __init__(self, key):
        if len(key) != 32:
            raise SSHCryptoError("AESGCM: key must be 32 bytes")
        import ctypes as _ct
        self._U8 = _ct.c_ubyte
        self._key = (self._U8 * 32).from_buffer_copy(key)
        self._key_b = bytes(key)

    def encrypt(self, nonce, pt, aad=b""):
        import ctypes as _ct
        if len(nonce) != 12: raise SSHCryptoError("nonce must be 12 bytes")
        U8 = self._U8
        nb = (U8 * 12).from_buffer_copy(nonce)
        aad_b = aad if isinstance(aad, bytes) else bytes(aad)
        ab = (U8 * len(aad_b)).from_buffer_copy(aad_b) if aad_b else None
        pb = (U8 * len(pt)).from_buffer_copy(pt) if pt else None
        out = (U8 * (len(pt) + 16))()
        rc = _PRIM_C.myssh_aes256_gcm_encrypt(
            self._key, nb,
            ab, len(aad_b),
            pb, len(pt),
            out)
        if rc != 0: raise SSHCryptoError("AES-GCM encrypt failed")
        return bytes(out)

    def decrypt(self, nonce, ct, aad=b""):
        import ctypes as _ct
        if len(nonce) != 12: raise SSHCryptoError("nonce must be 12 bytes")
        if len(ct) < 16: raise SSHCryptoError("ct too short")
        U8 = self._U8
        nb = (U8 * 12).from_buffer_copy(nonce)
        aad_b = aad if isinstance(aad, bytes) else bytes(aad)
        ab = (U8 * len(aad_b)).from_buffer_copy(aad_b) if aad_b else None
        cb = (U8 * len(ct)).from_buffer_copy(ct)
        pt_len = len(ct) - 16
        out = (U8 * pt_len)()
        rc = _PRIM_C.myssh_aes256_gcm_decrypt(
            self._key, nb,
            ab, len(aad_b),
            cb, len(ct),
            out)
        if rc != 0: raise SSHCryptoError("GCM tag mismatch")
        return bytes(out)


def _aes256_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CTR через C (libmyssh.so). iv — 16 байт big-endian."""
    if _PRIM_C is None:
        raise RuntimeError("libmyssh.so не загружена — _aes256_ctr недоступен")
    if len(key) != 32: raise ValueError("key must be 32 bytes")
    if len(iv)  != 16: raise ValueError("iv must be 16 bytes")
    import ctypes as _ct
    U8 = _ct.c_ubyte
    kb = (U8 * 32).from_buffer_copy(key)
    ib = (U8 * 16).from_buffer_copy(iv)
    n = len(data)
    db = (U8 * n).from_buffer_copy(data) if n else (U8 * 1)()
    ob = (U8 * n)() if n else (U8 * 1)()
    rc = _PRIM_C.myssh_aes256_ctr(kb, ib, db, n, ob)
    if rc != 0:
        raise RuntimeError(f"aes256_ctr failed: rc={rc}")
    return bytes(ob) if n else b""


def _ssh_string(b): return struct.pack(">I", len(b)) + b


def _pad(data, block=8):
    n = block - len(data) % block
    return data + bytes(range(1, n + 1))


def ssh_mpint(n):
    if n == 0: return struct.pack(">I", 0)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80: raw = b"\x00" + raw
    return struct.pack(">I", len(raw)) + raw


def read_string(buf, off=0):
    n = struct.unpack(">I", buf[off:off+4])[0]
    return buf[off+4:off+4+n], off + 4 + n


def ssh_namelist(names):
    s = ",".join(names).encode("ascii")
    return struct.pack(">I", len(s)) + s


def parse_namelist(buf, off):
    n = struct.unpack(">I", buf[off:off+4])[0]; off += 4
    s = buf[off:off+n].decode("ascii"); off += n
    return (s.split(",") if s else []), off


# ═══════════════════════════════════════════════════════════════════════
# 5. Keys
# ═══════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════
# Blowfish + bcrypt_pbkdf (OpenSSH) + AES-256-CTR.
# Константы Blowfish = hex-цифры π (считаются один раз при первом вызове).
# ═══════════════════════════════════════════════════════════════════════
import functools as _functools


# ═══════════════════════════════════════════════════════════════════════
# Исключения myssh
# ═══════════════════════════════════════════════════════════════════════

class SSHError(Exception):
    """База для всех ошибок myssh."""


class SSHLibraryError(SSHError):
    """libmyssh.so не найдена, не собирается или сломана."""


class SSHConnectError(SSHError):
    """TCP-подключение не удалось."""


class SSHTimeoutError(SSHConnectError):
    """Таймаут при подключении."""


class SSHProtocolError(SSHError):
    """Сервер прислал что-то не по RFC."""


class SSHHostKeyError(SSHProtocolError):
    """Host key не совпал / MITM."""


class SSHAuthError(SSHError):
    """Аутентификация не прошла."""


class SSHChannelError(SSHError):
    """Ошибка канала / exec / shell."""


class SSHCryptoError(SSHError):
    """Ошибка на уровне криптопримитивов."""


class SSHKeyError(SSHCryptoError):
    """Проблема с ключом."""



@_functools.lru_cache(maxsize=1)
def _load_primitives():
    """Загружает libmyssh.so. Каждый символ регистрируется независимо —
    отсутствующие не валят импорт."""
    import ctypes as _ct, pathlib as _pl, sysconfig as _sc
    libname = "libmyssh.so"
    here = _pl.Path(__file__).resolve().parent
    cands = []
    try:
        cands.append(_pl.Path(_sc.get_paths()["purelib"]) / libname)
    except Exception:
        pass
    try:
        import _ctypes as _ctm
        cands.append(_pl.Path(_ctm.__file__).resolve().parent / libname)
    except Exception:
        pass
    cands.append(here / libname)

    lib = None
    loaded_path = None
    for _p in cands:
        if not _p.exists(): continue
        try:
            lib = _ct.CDLL(str(_p))
            loaded_path = str(_p)
            break
        except OSError:
            continue
        if lib is None:
            msg = (
                "C библиотека отсутствует.\n"
                "Собрать её одной командой:\n"
                "    sh compile.sh\n"
                "Искал в:\n" + "\n".join(f"    {p}" for p in cands)
            )
            raise SSHLibraryError(msg)

    _U8 = _ct.c_ubyte; _PU8 = _ct.POINTER(_U8); _sz = _ct.c_size_t
    _CP = _ct.c_char_p; _CPV = _ct.c_void_p

    def _reg(name, args, ret=None):
        try:
            fn = getattr(lib, name)
            fn.argtypes = args
            if ret is not None:
                fn.restype = ret
        except AttributeError:
            pass

    _reg("myssh_x25519_scalarmult_base", [_PU8, _PU8], _ct.c_int)
    _reg("myssh_x25519_scalarmult", [_PU8, _PU8, _PU8], _ct.c_int)
    _reg("myssh_sha256", [_PU8, _sz, _PU8], None)
    _reg("myssh_sha512", [_PU8, _sz, _PU8], None)
    _reg("myssh_aes256_gcm_encrypt", [_PU8, _PU8, _PU8, _sz, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_aes256_gcm_decrypt", [_PU8, _PU8, _PU8, _sz, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_aes256_ctr", [_PU8, _PU8, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_bcrypt_pbkdf", [_CP, _sz, _CP, _sz, _CPV, _sz, _ct.c_uint32], _ct.c_int)
    _reg("myssh_ed25519_pubkey", [_PU8, _PU8], None)
    _reg("myssh_ed25519_sign", [_PU8, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_ed25519_verify", [_PU8, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_chacha20_poly1305_encrypt", [_PU8, _ct.c_uint64, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_chacha20_poly1305_decrypt", [_PU8, _ct.c_uint64, _PU8, _sz, _PU8], _ct.c_int)
    _reg("myssh_chacha20_poly1305_length",  [_PU8, _ct.c_uint64, _PU8, _ct.POINTER(_ct.c_uint32)], _ct.c_int)

    _reg("myssh_chacha20_poly1305_length",  [_PU8, _ct.c_uint64, _PU8, _ct.POINTER(_ct.c_uint32)], _ct.c_int)
    _reg("myssh_rsa_sign",   [_PU8, _sz, _ct.c_int, _PU8, _sz, _PU8, _ct.POINTER(_sz)], _ct.c_int)
    _reg("myssh_rsa_verify", [_PU8, _sz, _ct.c_int, _PU8, _sz, _PU8, _sz], _ct.c_int)

    # ML-KEM-768
    _reg("myssh_mlkem768_keygen", [_PU8, _PU8, _PU8], _ct.c_int)
    _reg("myssh_mlkem768_encaps", [_PU8, _PU8, _PU8, _PU8], _ct.c_int)
    _reg("myssh_mlkem768_decaps", [_PU8, _PU8, _PU8], _ct.c_int)
    _reg("myssh_sha3_256", [_PU8, _sz, _PU8], None)
    _reg("myssh_sha3_512", [_PU8, _sz, _PU8], None)

    return lib, loaded_path




_PRIM_C, _PRIM_C_PATH = _load_primitives()
if _PRIM_C is not None:
    print(f"[primitives] C backend: {_PRIM_C_PATH}")
else:
    print("[primitives] C backend: не загружен — крипта на C недоступна")
class _Ed25519_C:
    """Ed25519 на C. Совместим по API с Python-версией."""
    def __init__(self, seed):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        import ctypes as _ct
        self.seed = bytearray(seed)
        _U8 = _ct.c_ubyte
        sb = (_U8 * 32).from_buffer_copy(bytes(seed))
        pb = (_U8 * 32)()
        _PRIM_C.myssh_ed25519_pubkey(sb, pb)
        self._pub = bytes(pb)
        self._wiped = False

    @classmethod
    def generate(cls):
        import secrets as _s
        return cls(_s.token_bytes(32))

    @property
    def public_raw(self):
        return self._pub

    def wipe(self):
        if getattr(self, "_wiped", True): return
        for i in range(len(self.seed)): self.seed[i] = 0
        self._wiped = True

    def __del__(self):
        try: self.wipe()
        except Exception: pass

    def sign(self, msg):
        if self._wiped:
            raise RuntimeError("Ed25519: key wiped")
        import ctypes as _ct
        _U8 = _ct.c_ubyte; _sz = _ct.c_size_t
        sb = (_U8 * 32).from_buffer_copy(bytes(self.seed))
        mb = (_U8 * len(msg)).from_buffer_copy(msg) if msg else (_U8 * 1)()
        sig = (_U8 * 64)()
        rc = _PRIM_C.myssh_ed25519_sign(sb, mb, len(msg), sig)
        if rc != 0:
            raise SSHCryptoError("ed25519_sign failed")
        return bytes(sig)

    @classmethod
    def verify(cls, pub_raw, msg, sig):
        if len(pub_raw) != 32 or len(sig) != 64:
            return False
        import ctypes as _ct
        _U8 = _ct.c_ubyte; _sz = _ct.c_size_t
        pb = (_U8 * 32).from_buffer_copy(pub_raw)
        mb = (_U8 * len(msg)).from_buffer_copy(msg) if msg else (_U8 * 1)()
        sg = (_U8 * 64).from_buffer_copy(sig)
        rc = _PRIM_C.myssh_ed25519_verify(pb, mb, len(msg), sg)
        return rc == 1


# Ed25519 всегда C — Python-реализация удалена.
# Если .so не найдена, _load_primitives() бросит SSHLibraryError
# ДО этой строки, и мы сюда не дойдём.
Ed25519 = _Ed25519_C
print("[ed25519] C backend active")



def _bcrypt_pbkdf_c(password: bytes, salt: bytes, keylen: int, rounds: int) -> bytes:
    import ctypes as _ct
    _U8 = _ct.c_ubyte
    def _cb(b):
        return (_U8 * len(b)).from_buffer_copy(b) if b else (_U8 * 1)()
    out = (_U8 * keylen)()
    rc = _PRIM_C.myssh_bcrypt_pbkdf(_cb(password), len(password),
                                     _cb(salt), len(salt),
                                     out, keylen, rounds)
    if rc != 0:
        raise RuntimeError(f"bcrypt_pbkdf C failed: rc={rc}")
    return bytes(out)


def bcrypt_pbkdf(password, salt, keylen: int, rounds: int = 16) -> bytes:
    """bcrypt_pbkdf. C через libmyssh (c_char_p + c_void_p), иначе Python."""
    if isinstance(password, str): password = password.encode("utf-8")
    if isinstance(salt, str):     salt = salt.encode("utf-8")
    if _PRIM_C is not None:
        import ctypes as _ct
        out = (_ct.c_ubyte * keylen)()
        rc = _PRIM_C.myssh_bcrypt_pbkdf(
            password, len(password),
            salt, len(salt),
            out, keylen, rounds)
        if rc != 0:
            raise RuntimeError(f"bcrypt_pbkdf C failed: rc={rc}")
        return bytes(out)


def _bcrypt_pbkdf_py(password, salt, keylen: int, rounds: int = 16) -> bytes:
    """OpenSSH bcrypt_pbkdf. Совместим с ssh-keygen -N password."""
    if isinstance(password, str): password = password.encode("utf-8")
    if isinstance(salt, str):     salt = salt.encode("utf-8")
    if rounds < 1 or keylen == 0 or not password or not salt:
        raise ValueError("bcrypt_pbkdf: invalid parameters")

    sha2pass = hashlib.sha512(password).digest()
    stride   = (keylen + 31) // 32
    amt      = (keylen + stride - 1) // stride
    orig_keylen = keylen

    key = bytearray(keylen)
    remaining = keylen
    count = 1
    while remaining > 0:
        countsalt = salt + struct.pack(">I", count)
        sha2salt  = hashlib.sha512(countsalt).digest()

        tmpout = _bcrypt_hash(sha2pass, sha2salt)
        out = bytearray(tmpout)
        for _ in range(1, rounds):
            sha2salt = hashlib.sha512(tmpout).digest()
            tmpout = _bcrypt_hash(sha2pass, sha2salt)
            for j in range(32):
                out[j] ^= tmpout[j]

        amt2 = min(amt, remaining)
        written = 0
        for i in range(amt2):
            dest = i * stride + (count - 1)
            if dest >= orig_keylen: break
            key[dest] = out[i]
            written = i + 1
        remaining -= written
        count += 1

    return bytes(key)



def _parse_openssh_private(pem_text: str, password=None) -> bytes:
    """Парсит openssh-key-v1. Возвращает seed(32).
    Если ключ зашифрован и пароль задан — расшифровывает (bcrypt + aes256-ctr)."""
    lines = pem_text.strip().splitlines()
    body = "".join(l for l in lines if not l.startswith("-----"))
    blob = base64.b64decode(body)
    if not blob.startswith(b"openssh-key-v1\x00"):
        raise ValueError("not openssh-key-v1")

    off = 15
    cipher, off  = read_string(blob, off)
    kdf,    off  = read_string(blob, off)
    kdfopt, off  = read_string(blob, off)
    off += 4

    pub_blob,  off = read_string(blob, off)
    priv_blob, off = read_string(blob, off)

    if cipher == b"none":
        if kdf != b"none":
            raise ValueError("cipher=none but kdf!=none")
        private_block = priv_blob
    elif cipher == b"aes256-ctr":
        if kdf != b"bcrypt":
            raise NotImplementedError(f"cipher={cipher}, kdf={kdf}")
        if password is None:
            raise ValueError("ключ зашифрован, нужен password")
        salt, o2 = read_string(kdfopt, 0)
        rounds = struct.unpack(">I", kdfopt[o2:o2+4])[0]
        key_iv = bcrypt_pbkdf(password, salt, 48, rounds)
        aes_key, iv = key_iv[:32], key_iv[32:48]
        private_block = _aes256_ctr(priv_blob, aes_key, iv)
    else:
        raise NotImplementedError(f"cipher={cipher}")

    if len(private_block) < 8:
        raise SSHKeyError("private block too short")
    ci1, ci2 = struct.unpack(">II", private_block[:8])
    if ci1 != ci2:
        raise SSHKeyError("checkint mismatch — неверный пароль?")

    off2 = 8
    algo, off2 = read_string(private_block, off2)
    pub,  off2 = read_string(private_block, off2)
    priv64, off2 = read_string(private_block, off2)

    if algo.decode() != "ssh-ed25519":
        raise NotImplementedError(f"unsupported algo: {algo!r}")

    seed = priv64[:32]
    if Ed25519(seed).public_raw != pub:
        raise SSHKeyError("pubkey does not match private seed")
    return seed



class Key:
    KEYTYPE = "ssh-ed25519"

    def __init__(self, ed, role, comment=""):
        assert role in ("private", "public")
        self._ed = ed; self.role = role; self.comment = comment

    def bytes(self):
        return self._ed.seed if self.role == "private" else self._ed.public_raw

    def hex(self):    return bytes(self.bytes()).hex()
    def base64(self): return base64.b64encode(bytes(self.bytes())).decode()

    def public_blob(self):
        return _ssh_string(self.KEYTYPE.encode()) + _ssh_string(self._ed.public_raw)

    def _private_block_raw(self) -> bytes:
        """Сырой приватный блок БЕЗ padding."""
        ci = secrets.randbits(32)
        seed = bytes(self._ed.seed)
        return (struct.pack(">I", ci) + struct.pack(">I", ci)
                + _ssh_string(self.KEYTYPE.encode())
                + _ssh_string(self._ed.public_raw)
                + _ssh_string(seed + self._ed.public_raw)
                + _ssh_string(self.comment.encode()))

    def openssh_container(self, password=None, rounds=16) -> bytes:
        """
        openssh-key-v1 контейнер.
        password=None → ciphername=none (без шифрования).
        password=<str> → aes256-ctr + bcrypt_pbkdf (как ssh-keygen -N).
        """
        raw = self._private_block_raw()

        if password is None:
            ciphername = b"none"
            kdfname    = b"none"
            kdfoptions = b""
            private_block = _pad(raw, 8)
        else:
            ciphername = b"aes256-ctr"
            kdfname    = b"bcrypt"
            salt = secrets.token_bytes(16)
            kdfoptions = _ssh_string(salt) + struct.pack(">I", rounds)
            key_iv = bcrypt_pbkdf(password, salt, 48, rounds)
            aes_key, iv = key_iv[:32], key_iv[32:48]
            padded = _pad(raw, 16)
            private_block = _aes256_ctr(padded, aes_key, iv)

        return (b"openssh-key-v1\x00"
                + _ssh_string(ciphername)
                + _ssh_string(kdfname)
                + _ssh_string(kdfoptions)
                + struct.pack(">I", 1)
                + _ssh_string(self.public_blob())
                + _ssh_string(private_block))

    def to_openssh_private(self, password=None, rounds=16) -> str:
        container = self.openssh_container(password=password, rounds=rounds)
        b64 = base64.b64encode(container).decode()
        body = "\n".join(b64[i:i+70] for i in range(0, len(b64), 70))
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + body + "\n-----END OPENSSH PRIVATE KEY-----\n")

    def to_authorized_key(self):
        line = f"{self.KEYTYPE} {base64.b64encode(self.public_blob()).decode()}"
        return line + (f" {self.comment}" if self.comment else "") + "\n"

    @property
    def fingerprint(self):
        d = hashlib.sha256(self.public_blob()).digest()
        return "SHA256:" + base64.b64encode(d).decode().rstrip("=")

    def sign(self, msg):
        if self.role != "private": raise TypeError("public key cannot sign")
        return self._ed.sign(msg)

    def verify(self, msg, sig):
        return Ed25519.verify(self._ed.public_raw, msg, sig)

    def wipe(self):
        if self.role == "private": self._ed.wipe()

    def __del__(self):
        try: self.wipe()
        except Exception: pass

    def save(self, path, mode=None, password=None, rounds=16):
        if mode is None:
            mode = 0o600 if self.role == "private" else 0o644
        path = os.path.expanduser(path)
        if self.role == "private":
            data = self.to_openssh_private(password=password, rounds=rounds)
        else:
            data = self.to_authorized_key()
        with open(path, "w") as f: f.write(data)
        try: os.chmod(path, mode)
        except OSError: pass
        return os.path.abspath(path)

    @classmethod
    def load(cls, path, password=None):
        """Загрузить ключ из файла. Для зашифрованного нужен password."""
        path = os.path.expanduser(path)
        with open(path, "rb") as f:
            raw = f.read()
        if raw.lstrip().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            seed = _parse_openssh_private(raw.decode(), password=password)
            return Key(Ed25519(seed), "private")
        text = raw.decode("utf-8", errors="replace").strip()
        if text.startswith("ssh-ed25519 "):
            parts = text.split(None, 2)
            blob = base64.b64decode(parts[1])
            algo, o = read_string(blob, 0)
            pub,  o = read_string(blob, o)
            return _PublicOnlyKey(pub)
        if len(raw) == 32:
            return Key(Ed25519(raw), "private")
        raise SSHKeyError("unrecognized key format")

    def __repr__(self):
        return f"<Key {self.role} {self.KEYTYPE} {len(self.bytes())}B>"



class _PublicOnlyKey(Key):
    """Публичный ключ без seed — sign() запрещён."""
    def __init__(self, pub_raw, comment=""):
        self._pub_raw = pub_raw
        self.role = "public"
        self.comment = comment
        self._ed = None

    def bytes(self): return self._pub_raw
    def public_blob(self):
        return _ssh_string(self.KEYTYPE.encode()) + _ssh_string(self._pub_raw)
    def sign(self, msg): raise TypeError("public-only key cannot sign")
    def verify(self, msg, sig):
        return Ed25519.verify(self._pub_raw, msg, sig)
    def wipe(self): pass


# ═══════════════════════════════════════════════════════════════════════
# RSA — keygen в Python, sign/verify через C
# ═══════════════════════════════════════════════════════════════════════

import secrets as _rsa_secrets


# ---- Miller-Rabin ----
_RSA_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def _rsa_is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2: return False
    for sp in _RSA_SMALL_PRIMES:
        if n == sp: return True
        if n % sp == 0: return False
    d = n - 1
    r = 0
    while not (d & 1):
        d >>= 1
        r += 1
    for _ in range(rounds):
        a = _rsa_secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _rsa_gen_prime(bits: int) -> int:
    while True:
        n = _rsa_secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _rsa_is_probable_prime(n):
            return n


def _int_to_mpint(n: int) -> bytes:
    if n == 0:
        return struct.pack(">I", 0)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return struct.pack(">I", len(raw)) + raw


def _rsa_priv_blob(n, e, d, iqmp, p, q) -> bytes:
    return (_int_to_mpint(n) + _int_to_mpint(e) + _int_to_mpint(d)
            + _int_to_mpint(iqmp) + _int_to_mpint(p) + _int_to_mpint(q))


def _rsa_pub_blob(n, e) -> bytes:
    return _int_to_mpint(e) + _int_to_mpint(n)


class RSAKey:
    """
    RSA-ключ. Параллельен Key (Ed25519), с тем же интерфейсом:
      sign/verify/public_blob/fingerprint
    Но public_blob возвращает SSH-блоб с типом "ssh-rsa" или "rsa-sha2-256".

    Хранит:
      n, e — публичные
      d, iqmp, p, q — приватные (только для role="private")
    """
    KEYTYPE = "ssh-rsa"        # для подписи — rsa-sha2-256
    SIGTYPE = "rsa-sha2-256"   # что пошлём в подписи

    def __init__(self, n, e, d=None, iqmp=None, p=None, q=None,
                 role="private", comment=""):
        self.n = n
        self.e = e
        self.d = d
        self.iqmp = iqmp
        self.p = p
        self.q = q
        self.role = role
        self.comment = comment
        if role == "private" and (d is None or p is None or q is None):
            raise ValueError("private RSAKey требует d, p, q")

    @classmethod
    def generate(cls, bits: int = 2048, comment: str = "") -> "RSAKey":
        e = 65537
        while True:
            p = _rsa_gen_prime(bits // 2)
            q = _rsa_gen_prime(bits - bits // 2)
            if p == q: continue
            n = p * q
            if n.bit_length() != bits: continue
            phi = (p - 1) * (q - 1)
            if phi % e == 0: continue
            d = pow(e, -1, phi)
            if q > p: p, q = q, p
            iqmp = pow(q, -1, p)
            return cls(n, e, d, iqmp, p, q, "private", comment)

    @classmethod
    def from_components(cls, n, e, d=None, iqmp=None, p=None, q=None,
                        comment=""):
        role = "private" if d is not None else "public"
        return cls(n, e, d, iqmp, p, q, role, comment)

    @property
    def bits(self): return self.n.bit_length()
    @property
    def size_bytes(self): return (self.bits + 7) // 8

    def _pub_blob_bytes(self) -> bytes:
        """Для C-verify: только mpint(e) || mpint(n), без префикса keytype."""
        return _int_to_mpint(self.e) + _int_to_mpint(self.n)

    def public_blob(self) -> bytes:
        """SSH-блоб публичного ключа: string("ssh-rsa") || mpint(e) || mpint(n)."""
        return _ssh_string(b"ssh-rsa") + _int_to_mpint(self.e) + _int_to_mpint(self.n)

    @property
    def fingerprint(self) -> str:
        d = hashlib.sha256(self.public_blob()).digest()
        return "SHA256:" + base64.b64encode(d).decode().rstrip("=")

    def _priv_blob_bytes(self) -> bytes:
        return _rsa_priv_blob(self.n, self.e, self.d, self.iqmp, self.p, self.q)

    def sign(self, msg: bytes, hash_algo: str = "sha2-256") -> bytes:
        """Подписывает msg. Возвращает raw_sig (без SSH-обёртки).
        hash_algo: "sha2-256" (default) или "sha2-512"."""
        if self.role != "private":
            raise TypeError("public RSAKey cannot sign")

        if hash_algo in ("sha2-256", "rsa-sha2-256"):
            h = hashlib.sha256(msg).digest()
            algo_c = 1
        elif hash_algo in ("sha2-512", "rsa-sha2-512"):
            h = hashlib.sha512(msg).digest()
            algo_c = 2
        else:
            raise ValueError(f"unknown hash_algo: {hash_algo}")

        import ctypes as _ct
        U8 = _ct.c_ubyte
        priv = self._priv_blob_bytes()
        pb = (U8 * len(priv)).from_buffer_copy(priv)
        mb = (U8 * len(h)).from_buffer_copy(h)
        sig_buf = (U8 * 512)()
        sig_len = _ct.c_size_t(512)
        rc = _PRIM_C.myssh_rsa_sign(pb, len(priv), algo_c,
                                     mb, len(h),
                                     sig_buf, _ct.byref(sig_len))
        if rc != 0:
            raise SSHCryptoError(f"rsa sign failed: rc={rc}")
        return bytes(sig_buf[:sig_len.value])

    def verify(self, msg: bytes, raw_sig: bytes,
               algo_name: str = "rsa-sha2-256") -> bool:
        """raw_sig — то что вернул sign(). algo_name — "rsa-sha2-256"/"rsa-sha2-512"."""
        if algo_name in ("rsa-sha2-256", "sha2-256"):
            h = hashlib.sha256(msg).digest(); algo_c = 1
        elif algo_name in ("rsa-sha2-512", "sha2-512"):
            h = hashlib.sha512(msg).digest(); algo_c = 2
        else:
            return False

        import ctypes as _ct
        U8 = _ct.c_ubyte
        pub = self._pub_blob_bytes()
        pbuf = (U8 * len(pub)).from_buffer_copy(pub)
        hbuf = (U8 * len(h)).from_buffer_copy(h)
        sbuf = (U8 * len(raw_sig)).from_buffer_copy(raw_sig)
        rc = _PRIM_C.myssh_rsa_verify(pbuf, len(pub), algo_c,
                                       hbuf, len(h),
                                       sbuf, len(raw_sig))
        return rc == 1

    def wipe(self):
        self.d = 0; self.p = 0; self.q = 0; self.iqmp = 0

    def __del__(self):
        try: self.wipe()
        except Exception: pass

    def __repr__(self):
        return f"<RSAKey {self.role} {self.bits}b>"


class RSAKeys:
    """Пара RSA-ключей, аналогично SSHKeys."""
    def __init__(self, bits=2048, comment=""):
        k = RSAKey.generate(bits=bits, comment=comment)
        self._k = k
        self.private_key = k
        # Публичная часть — тот же объект, но с role="public" и без приватных полей
        self.public_key = RSAKey(k.n, k.e, None, None, None, None,
                                  "public", comment)

    def __iter__(self):
        return iter((self.private_key, self.public_key))

    def __repr__(self):
        return f"<RSAKeys {self.public_key.bits}b fp={self.public_key.fingerprint}>"


class SSHKeys:
    def __init__(self, seed=None, comment=""):
        ed = Ed25519(seed) if seed else Ed25519.generate()
        self._ed = ed
        self.comment = comment
        self.private_key = Key(ed, "private", comment)
        self.public_key  = Key(ed, "public",  comment)

    @classmethod
    def from_hex(cls, h, comment=""):
        return cls(seed=bytes.fromhex(h), comment=comment)

    def __iter__(self): return iter((self.private_key, self.public_key))
    def wipe(self): self.private_key.wipe()
    def __enter__(self): return self
    def __exit__(self, *a): self.wipe()
    def __del__(self):
        try: self.wipe()
        except Exception: pass
    def __repr__(self):
        return f"<SSHKeys fp={self.public_key.fingerprint}>"


# ═══════════════════════════════════════════════════════════════════════
# 6. known_hosts
# ═══════════════════════════════════════════════════════════════════════
def _kh_path(): return os.path.expanduser("~/.ssh/known_hosts")
def _kh_normalize(host, port): return host if port == 22 else f"[{host}]:{port}"


def _kh_load(path=None):
    path = path or _kh_path()
    entries = {}
    if not os.path.exists(path): return entries
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split()
            if len(parts) < 3: continue
            for h in parts[0].split(","):
                entries.setdefault(h, []).append((parts[1], parts[2]))
    return entries


def _kh_matches_hashed(pattern, host):
    if not pattern.startswith("|1|"): return False
    try:
        _, _, salt_b64, hash_b64 = pattern.split("|", 3)
        pad = lambda s: s + "=" * (-len(s) % 4)
        salt = base64.b64decode(pad(salt_b64))
        expected = base64.b64decode(pad(hash_b64))
        actual = hmac.new(salt, host.encode(), hashlib.sha1).digest()
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def _kh_check(entries, host, port, keytype, pubkey_blob):
    target = _kh_normalize(host, port)
    b64 = base64.b64encode(pubkey_blob).decode().rstrip("=")
    host_seen = False
    for pattern, keys in entries.items():
        if pattern == target or _kh_matches_hashed(pattern, target):
            host_seen = True
            for (kt, k) in keys:
                if kt == keytype and k.rstrip("=") == b64:
                    return "match"
    return "mismatch" if host_seen else "unknown"


def _kh_append(path, host, port, keytype, pubkey_blob):
    path = path or _kh_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    target = _kh_normalize(host, port)
    b64 = base64.b64encode(pubkey_blob).decode().rstrip("=")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{target} {keytype} {b64}\n")


# ═══════════════════════════════════════════════════════════════════════
# 7. Protocol constants
# ═══════════════════════════════════════════════════════════════════════
MSG_DISCONNECT       = 1
MSG_IGNORE           = 2
MSG_UNIMPLEMENTED    = 3
MSG_DEBUG            = 4
MSG_SERVICE_REQUEST  = 5
MSG_SERVICE_ACCEPT   = 6
MSG_EXT_INFO         = 7
MSG_KEXINIT          = 20
MSG_NEWKEYS          = 21
MSG_KEX_ECDH_INIT    = 30
MSG_KEX_ECDH_REPLY   = 31
MSG_USERAUTH_REQUEST = 50
MSG_USERAUTH_FAILURE = 51
MSG_USERAUTH_SUCCESS = 52
MSG_USERAUTH_BANNER  = 53
MSG_USERAUTH_PK_OK   = 60
MSG_GLOBAL_REQUEST            = 80
MSG_REQUEST_SUCCESS           = 81
MSG_REQUEST_FAILURE           = 82
MSG_CHANNEL_OPEN              = 90
MSG_CHANNEL_OPEN_CONFIRMATION = 91
MSG_CHANNEL_OPEN_FAILURE      = 92
MSG_CHANNEL_WINDOW_ADJUST     = 93
MSG_CHANNEL_DATA              = 94
MSG_CHANNEL_EXTENDED_DATA     = 95
MSG_CHANNEL_EOF               = 96
MSG_CHANNEL_CLOSE             = 97
MSG_CHANNEL_REQUEST           = 98
MSG_CHANNEL_SUCCESS           = 99
MSG_CHANNEL_FAILURE           = 100

DISC_BY_APPLICATION = 11
DISC_PROTOCOL_ERROR = 2

DEFAULT_KEX = ["mlkem768x25519-sha256",
               "curve25519-sha256", "curve25519-sha256@libssh.org"]
DEFAULT_HOSTKEY = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]
DEFAULT_CIPHERS = ["aes256-gcm@openssh.com"]
DEFAULT_MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"]
DEFAULT_COMPRESSION = ["none"]


def build_disconnect(reason, description=""):
    return (bytes([MSG_DISCONNECT])
            + struct.pack(">I", reason)
            + _ssh_string(description.encode())
            + _ssh_string(b""))


def build_kexinit(hostkey_algos=None):
    """hostkey_algos: список предпочтений сервера, по умолчанию DEFAULT_HOSTKEY."""
    if hostkey_algos is None:
        hostkey_algos = DEFAULT_HOSTKEY
    return (bytes([MSG_KEXINIT]) + secrets.token_bytes(16)
            + ssh_namelist(DEFAULT_KEX) + ssh_namelist(hostkey_algos)
            + ssh_namelist(DEFAULT_CIPHERS) + ssh_namelist(DEFAULT_CIPHERS)
            + ssh_namelist(DEFAULT_MACS) + ssh_namelist(DEFAULT_MACS)
            + ssh_namelist(DEFAULT_COMPRESSION) + ssh_namelist(DEFAULT_COMPRESSION)
            + ssh_namelist([]) + ssh_namelist([])
            + b"\x00" + struct.pack(">I", 0))


def parse_kexinit(payload):
    off = 1
    cookie = payload[off:off+16]; off += 16
    r = {"cookie": cookie}
    for name in ["kex","hostkey","enc_c2s","enc_s2c","mac_c2s","mac_s2c",
                 "comp_c2s","comp_s2c","lang_c2s","lang_s2c"]:
        r[name], off = parse_namelist(payload, off)
    r["first_kex_packet_follows"] = bool(payload[off]); off += 1
    r["reserved"] = struct.unpack(">I", payload[off:off+4])[0]
    return r


def negotiate(their, hostkey_algos=None):
    """hostkey_algos: наши предпочтения hostkey.
    Для клиента — DEFAULT_HOSTKEY (все поддерживаемые).
    Для сервера — только те, что есть у сервера."""
    if hostkey_algos is None:
        hostkey_algos = DEFAULT_HOSTKEY

    def pick(mine, theirs):
        for a in mine:
            if a in theirs: return a
        return None
    return {
        "kex":       pick(DEFAULT_KEX,         their["kex"]),
        "hostkey":   pick(hostkey_algos,       their["hostkey"]),
        "enc_c2s":   pick(DEFAULT_CIPHERS,     their["enc_c2s"]),
        "enc_s2c":   pick(DEFAULT_CIPHERS,     their["enc_s2c"]),
        "mac_c2s":   pick(DEFAULT_MACS,        their["mac_c2s"]),
        "mac_s2c":   pick(DEFAULT_MACS,        their["mac_s2c"]),
        "comp_c2s":  pick(DEFAULT_COMPRESSION, their["comp_c2s"]),
        "comp_s2c":  pick(DEFAULT_COMPRESSION, their["comp_s2c"]),
    }


def derive_key(K_ser, H, session_id, letter, length):
    out = hashlib.sha256(K_ser + H + letter + session_id).digest()
    while len(out) < length:
        out += hashlib.sha256(K_ser + H + out).digest()
    return out[:length]


def _mlkem768x25519_shared(mlkem_ss, x25519_ss):
    """K = SHA256(mlkem_ss || x25519_ss)."""
    return hashlib.sha256(mlkem_ss + x25519_ss).digest()


def compute_exchange_hash(V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K_raw):
    h = hashlib.sha256()
    h.update(_ssh_string(V_C.encode()))
    h.update(_ssh_string(V_S.encode()))
    h.update(_ssh_string(I_C))
    h.update(_ssh_string(I_S))
    h.update(_ssh_string(K_S))
    h.update(_ssh_string(Q_C))
    h.update(_ssh_string(Q_S))
    K_ser = ssh_mpint(int.from_bytes(K_raw, "big"))
    h.update(K_ser)
    return h.digest(), K_ser


def build_userauth_request(user, service, method, algo, pubkey_blob, has_sig):
    return (bytes([MSG_USERAUTH_REQUEST])
            + _ssh_string(user.encode())
            + _ssh_string(service.encode())
            + _ssh_string(method.encode())
            + (b"\x01" if has_sig else b"\x00")
            + _ssh_string(algo.encode())
            + _ssh_string(pubkey_blob))


def build_userauth_password(user, service, password):
    return (bytes([MSG_USERAUTH_REQUEST])
            + _ssh_string(user.encode())
            + _ssh_string(service.encode())
            + _ssh_string(b"password")
            + b"\x00"
            + _ssh_string(password.encode()))


def sign_userauth(session_id, request_bytes, private_key):
    """Подписывает USERAUTH_REQUEST. Возвращает request_bytes || string(sig_blob).
    sig_blob = string(sig_algo) || string(raw_sig).
    Поддерживает Ed25519 и RSA (rsa-sha2-256)."""
    to_sign = _ssh_string(session_id) + request_bytes

    keytype = getattr(private_key, "KEYTYPE", "ssh-ed25519")
    if keytype == "ssh-ed25519":
        raw_sig = private_key.sign(to_sign)
        sig_algo_name = b"ssh-ed25519"
    elif keytype == "ssh-rsa":
        raw_sig = private_key.sign(to_sign, hash_algo="sha2-256")
        sig_algo_name = b"rsa-sha2-256"
    else:
        raise SSHKeyError(f"unsupported KEYTYPE for sign_userauth: {keytype!r}")

    sig_blob = _ssh_string(sig_algo_name) + _ssh_string(raw_sig)
    return request_bytes + _ssh_string(sig_blob)



# ═══════════════════════════════════════════════════════════════════════
# 8. Packetizer + Transport
# ═══════════════════════════════════════════════════════════════════════
class Packetizer:
    """
    Binary packet protocol (RFC 4253 §6 + OpenSSH).
    Поддерживает:
      - plaintext (до NEWKEYS)
      - aes256-gcm@openssh.com (RFC 5647)
      - chacha20-poly1305@openssh.com (PROTOCOL.chacha20poly1305)
    """
    BLOCK = 8
    AEAD_BLOCK = 16
    MAX_LEN = 35000

    def __init__(self, sock, is_client=True):
        self.sock = sock
        self.is_client = is_client
        self.seq_send = 0
        self.seq_recv = 0
        self.cipher = None
        self.aes_send = self.aes_recv = None
        self.iv_send = self.iv_recv = None
        self.chacha_key_send = None
        self.chacha_key_recv = None
        self._block = self.BLOCK

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            ch = self.sock.recv(n - len(buf))
            if not ch: raise EOFError(f"closed ({len(buf)}/{n})")
            buf += ch
        return buf

    @staticmethod
    def _inc_iv(iv):
        """Инкремент IV как big-endian, in-place."""
        for i in range(len(iv) - 1, -1, -1):
            iv[i] = (iv[i] + 1) & 0xFF
            if iv[i] != 0:
                return
        raise SSHCryptoError("GCM nonce wrapped: rekey required")

    def enable_encryption(self, cipher, key_c2s, key_s2c,
                          iv_c2s=None, iv_s2c=None):
        """
        cipher:
          "aes256-gcm@openssh.com"          — key 32, iv 12
          "chacha20-poly1305@openssh.com"   — key 64, iv не нужен
        """
        self.cipher = cipher

        if cipher == "aes256-gcm@openssh.com":
            if self.is_client:
                self.aes_send, self.aes_recv = AESGCM(key_c2s), AESGCM(key_s2c)
                self.iv_send, self.iv_recv = bytearray(iv_c2s), bytearray(iv_s2c)
            else:
                self.aes_send, self.aes_recv = AESGCM(key_s2c), AESGCM(key_c2s)
                self.iv_send, self.iv_recv = bytearray(iv_s2c), bytearray(iv_c2s)
            self._block = self.AEAD_BLOCK

        elif cipher == "chacha20-poly1305@openssh.com":
            if self.is_client:
                self.chacha_key_send = key_c2s
                self.chacha_key_recv = key_s2c
            else:
                self.chacha_key_send = key_s2c
                self.chacha_key_recv = key_c2s
            self._block = self.BLOCK   # chacha: padding block = 8

        else:
            raise SSHCryptoError(f"неизвестный cipher: {cipher!r}")

    def _calc_pad(self, payload_len):
        # OpenSSH 10.x:
        #  plaintext:   (packet_length - 4) % block == 0
        #  encrypted:   packet_length        % block == 0
        block = self._block
        if self.cipher is None:
            pad = (3 - payload_len) % block
        else:
            pad = (-(1 + payload_len)) % block
        if pad < 4:
            pad += block
        return pad


    # ---------- отправка ----------
    def send(self, payload):
        pad = self._calc_pad(len(payload))
        padding = secrets.token_bytes(pad)
        pt = bytes([pad]) + payload + padding     # это N байт

        if self.cipher is None:
            # plaintext: [len(4)] + pt
            _hdr = struct.pack(">I", len(pt))
            self.sock.sendall(_hdr + pt)

        elif self.cipher == "aes256-gcm@openssh.com":
            # AES-GCM: len(4, AAD) + ct(pt) + tag(16)
            aad = struct.pack(">I", len(pt))
            ct = self.aes_send.encrypt(bytes(self.iv_send), pt, aad)
            self._inc_iv(self.iv_send)
            self.sock.sendall(aad + ct)

        else:
            # ChaCha20-Poly1305@openssh.com:
            #   C ждёт pt = [padding_length] [payload] [padding] (БЕЗ packet_length)
            #   C сам знает, что packet_length = pt_len, и шифрует его K_2.
            #   Выход: [enc_length (4)] [enc_pt (pt_len)] [tag (16)]
            import ctypes as _ct
            U8 = _ct.c_ubyte
            kb = (U8 * 64).from_buffer_copy(self.chacha_key_send)
            pb = (U8 * len(pt)).from_buffer_copy(pt)
            out = (U8 * (len(pt) + 20))()
            rc = _PRIM_C.myssh_chacha20_poly1305_encrypt(
                kb, self.seq_send, pb, len(pt), out)
            if rc != 0:
                raise SSHCryptoError("chacha encrypt failed")
            ob = bytes(out)
            self.sock.sendall(ob)

        self.seq_send = (self.seq_send + 1) & 0xFFFFFFFF

    # ---------- приём ----------
    def recv(self):
        if self.cipher is None:
            header = self._read_exact(4)
            packet_length = struct.unpack(">I", header)[0]
            if packet_length < 5 or packet_length > self.MAX_LEN:
                raise SSHProtocolError(f"bad packet_length: {packet_length}")
            body = self._read_exact(packet_length)
            pad = body[0]
            payload = body[1:len(body) - pad]

        elif self.cipher == "aes256-gcm@openssh.com":
            header = self._read_exact(4)
            packet_length = struct.unpack(">I", header)[0]
            if packet_length < 5 or packet_length > self.MAX_LEN:
                raise SSHProtocolError(f"bad packet_length: {packet_length}")
            ct = self._read_exact(packet_length + 16)
            pt = self.aes_recv.decrypt(bytes(self.iv_recv), ct, header)
            self._inc_iv(self.iv_recv)
            pad = pt[0]
            payload = pt[1:len(pt) - pad]

        else:
            # ChaCha: 4 enc len + N ct + 16 tag
            import ctypes as _ct
            U8 = _ct.c_ubyte
            len_ct = self._read_exact(4)
            kb = (U8 * 64).from_buffer_copy(self.chacha_key_recv)
            lcb = (U8 * 4).from_buffer_copy(len_ct)
            n = _ct.c_uint32()
            rc = _PRIM_C.myssh_chacha20_poly1305_length(
                kb, self.seq_recv, lcb, _ct.byref(n))
            if rc != 0:
                raise SSHCryptoError("chacha length decrypt failed")
            N = n.value
            if N < 5 or N > self.MAX_LEN:
                raise SSHProtocolError(f"bad packet_length: {N}")
            rest = self._read_exact(N + 16)   # enc_payload + tag
            full = len_ct + rest
            full_buf = (U8 * len(full)).from_buffer_copy(full)
            pt_buf = (U8 * N)()
            rc = _PRIM_C.myssh_chacha20_poly1305_decrypt(
                kb, self.seq_recv, full_buf, len(full), pt_buf)
            if rc != 0:
                raise SSHCryptoError("chacha auth failed (tag mismatch)")
            pt = bytes(pt_buf)
            pad = pt[0]
            payload = pt[1:len(pt) - pad]

        self.seq_recv = (self.seq_recv + 1) & 0xFFFFFFFF
        return payload


class Transport:
    def __init__(self, sock, version, is_client=True):
        self.sock = sock
        self.version = version
        self.is_client = is_client
        self.packetizer = Packetizer(sock, is_client=is_client)
        self.remote_version = None

    def _read_version_line(self):
        line = b""
        while True:
            ch = self.sock.recv(1)
            if not ch: raise EOFError("closed during version exchange")
            line += ch
            if line.endswith(b"\n"): break
            if len(line) > 255: raise ValueError("version too long")
        return line

    def exchange_versions(self):
        if self.is_client:
            while True:
                line = self._read_version_line()
                if line.startswith(b"SSH-"):
                    self.remote_version = line.rstrip(b"\r\n").decode()
                    break
            self.sock.sendall(self.version.encode() + b"\r\n")
        else:
            self.sock.sendall(self.version.encode() + b"\r\n")
            while True:
                line = self._read_version_line()
                if line.startswith(b"SSH-"):
                    self.remote_version = line.rstrip(b"\r\n").decode()
                    break
        return self.version, self.remote_version

    def send(self, payload): self.packetizer.send(payload)
    def recv(self):          return self.packetizer.recv()


# ═══════════════════════════════════════════════════════════════════════
# 9. Username + heredoc helpers
# ═══════════════════════════════════════════════════════════════════════
_FAKE_USERS = {"user", "unknown", "root", ""}
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([^\s'\"]+)\1\s*$")


def _get_username() -> str:
    """Реальное имя пользователя.

    На Android/Pydroid3 env[USER] может быть None или 'user' (заглушка).
    Авторитетный источник — ядро через `id -un`; env используем как fallback.
    """
    try:
        out = subprocess.check_output(["id", "-un"],
                                      stderr=subprocess.DEVNULL, timeout=2)
        v = out.decode(errors="replace").strip()
        if v and v not in _FAKE_USERS:
            return v
    except Exception:
        pass
    for k in ("USER", "LOGNAME", "USERNAME"):
        v = os.environ.get(k)
        if v and v not in _FAKE_USERS:
            return v
    try:
        import getpass
        v = getpass.getuser()
        if v and v not in _FAKE_USERS:
            return v
    except Exception:
        pass
    try:
        import pwd
        v = pwd.getpwuid(os.getuid()).pw_name
        if v and v not in _FAKE_USERS:
            return v
    except Exception:
        pass
    return "user"


def _detect_heredoc(line: str):
    """Если строка заканчивается на << MARKER или << 'MARKER', вернуть MARKER."""
    m = _HEREDOC_RE.search(line)
    return m.group(2) if m else None


# ═══════════════════════════════════════════════════════════════════════
# 10. SSH client
# ═══════════════════════════════════════════════════════════════════════
class SSH:
    VERSION = "SSH-2.0-MySSH_0.1"

    def __init__(self, pub, priv, addr, timeout=20, verbose=False,
                 known_hosts="auto", strict=True):
        self.pub, self.priv = pub, priv
        self.host, self.port = addr
        self.verbose = verbose
        self.remote_channel = None
        self.local_channel = None
        self.known_hosts_path = (
            None if known_hosts is None
            else (os.path.expanduser("~/.ssh/known_hosts")
                  if known_hosts == "auto" else known_hosts))
        self.strict = strict
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.transport = Transport(self.sock, self.VERSION, is_client=True)

        _, remote_v = self.transport.exchange_versions()
        self.remote_version = remote_v
        if verbose: print(f"       server: {remote_v}")

        self.my_kexinit = build_kexinit()
        self.transport.send(self.my_kexinit)
        if verbose: print("       -> KEXINIT")

        self.their_kexinit_raw = self.transport.recv()
        self.their_kexinit = parse_kexinit(self.their_kexinit_raw)
        if verbose: print("       <- KEXINIT")

        self.algorithms = negotiate(self.their_kexinit)
        if (self.algorithms["kex"] is None or
            self.algorithms["hostkey"] is None or
            self.algorithms["enc_c2s"] is None):
            raise SSHProtocolError(f"no common algorithms: {self.algorithms}")
        self._do_kex()
        self._service_request("ssh-userauth")

    def _check_kex_consistency(self, hk_type, sig_type, K_S):
        chosen = self.algorithms["hostkey"]
        # host key blob name должен быть одним из ssh-ed25519 / ssh-rsa / rsa-sha2-*
        blob_name, _ = read_string(K_S, 0)
        blob_name = blob_name.decode()

        # Для RSA сервер может вернуть blob "ssh-rsa" даже если в KEXINIT
        # мы выбрали "rsa-sha2-256"/"rsa-sha2-512" — это разрешено RFC 8332.
        if blob_name == "ssh-rsa" and chosen in ("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"):
            pass
        elif blob_name in ("rsa-sha2-256", "rsa-sha2-512") and chosen in ("rsa-sha2-256", "rsa-sha2-512"):
            pass
        elif blob_name == chosen:
            pass
        else:
            raise SSHHostKeyError(f"host key blob name mismatch: {blob_name} vs {chosen}")

        # Проверка совместимости sig_type и hk_type
        if blob_name == "ssh-ed25519":
            if sig_type != "ssh-ed25519":
                raise SSHHostKeyError(f"bad sig type for ed25519: {sig_type}")
        elif blob_name == "ssh-rsa":
            if sig_type not in ("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"):
                raise SSHHostKeyError(f"bad sig type for rsa: {sig_type}")
        else:
            raise SSHHostKeyError(f"unsupported host key: {blob_name}")

    def _do_kex(self):
        kex = self.algorithms["kex"]
        if kex == "mlkem768x25519-sha256":
            return self._do_kex_mlkem768x25519()
        # Fallback: curve25519-sha256
        return self._do_kex_curve25519()

    def _do_kex_mlkem768x25519(self):
        """Гибридный KEX ML-KEM-768 + X25519 + SHA-256 (OpenSSH 9.9+)."""
        # Клиент генерирует ML-KEM keypair + X25519 keypair
        mlkem_ek, mlkem_dk = MLKEM768.keygen()
        x_priv = secrets.token_bytes(32)
        x_pub = X25519.scalarmult_base(x_priv)

        # C_INIT = mlkem_ek(1184) || x25519_pub(32) = 1216 байт
        c_init = mlkem_ek + x_pub
        self.transport.send(bytes([MSG_KEX_ECDH_INIT]) + _ssh_string(c_init))
        if self.verbose:
            print(f"       -> KEX_ECDH_INIT (mlkem768x25519, {len(c_init)} байт)")

        reply = self.transport.recv()
        off = 1
        K_S,   off = read_string(reply, off)
        s_reply, off = read_string(reply, off)
        sig_b, off = read_string(reply, off)
        if self.verbose: print("       <- KEX_ECDH_REPLY")

        # Разбираем S_REPLY = mlkem_ct(1088) || x25519_pub_server(32) = 1120 байт
        if len(s_reply) != 1120:
            raise SSHProtocolError(f"bad S_REPLY len: {len(s_reply)} (expected 1120)")
        mlkem_ct = s_reply[:1088]
        x_srv_pub = s_reply[1088:]

        # ML-KEM decaps
        mlkem_ss = MLKEM768.decaps(mlkem_ct, mlkem_dk)
        # X25519
        x_ss = X25519.scalarmult(x_priv, x_srv_pub)
        # K = SHA256(mlkem_ss || x25519_ss)
        K_raw = _mlkem768x25519_shared(mlkem_ss, x_ss)

        self._finish_kex(K_S, c_init, s_reply, K_raw, sig_b)

    def _do_kex_curve25519(self):
        """Классический curve25519-sha256."""
        eph_priv = secrets.token_bytes(32)
        eph_pub  = X25519.scalarmult_base(eph_priv)
        self.transport.send(bytes([MSG_KEX_ECDH_INIT]) + _ssh_string(eph_pub))
        if self.verbose: print("       -> KEX_ECDH_INIT")

        reply = self.transport.recv()
        off = 1
        K_S,   off = read_string(reply, off)
        Q_S,   off = read_string(reply, off)
        sig_b, off = read_string(reply, off)
        if self.verbose: print("       <- KEX_ECDH_REPLY")

        K_raw = X25519.scalarmult(eph_priv, Q_S)
        self._finish_kex(K_S, eph_pub, Q_S, K_raw, sig_b)

    def _finish_kex(self, K_S, Q_C_bytes, Q_S_bytes, K_raw, sig_b):
        """Общая часть: H, проверка подписи, NEWKEYS, key derivation."""
        # Для curve25519 K_raw = X25519 shared (32 байта, mpint).
        # Для mlkem768x25519 K_raw = SHA256(mlkem_ss || x25519_ss) (32 байта, string).
        kex = self.algorithms["kex"]
        if kex == "mlkem768x25519-sha256":
            # K_ser = string(K) — не mpint!
            K_ser = _ssh_string(K_raw)
        else:
            K_ser = ssh_mpint(int.from_bytes(K_raw, "big"))
            K_ser = ssh_mpint(int.from_bytes(K_raw, "big"))  # уже mpint

        # compute_exchange_hash теперь принимает готовый K_ser
        H, K_ser = self._compute_H(K_S, Q_C_bytes, Q_S_bytes, K_ser)

        # Разбор sig_b
        sig_type, o = read_string(sig_b, 0)
        sig_bytes, o = read_string(sig_b, o)
        hk_type_b, o = read_string(K_S, 0)
        hk_type = hk_type_b.decode()

        # Парсинг pubkey по типу
        if hk_type == "ssh-ed25519":
            hk_pub, o = read_string(K_S, o)
            rsa_e_b = rsa_n_b = None
        elif hk_type == "ssh-rsa":
            rsa_e_b, o = read_string(K_S, o)
            rsa_n_b, o = read_string(K_S, o)
            hk_pub = None
        else:
            raise SSHHostKeyError(f"unsupported host key: {hk_type}")

        sig_type = sig_type.decode()
        self._check_kex_consistency(hk_type, sig_type, K_S)

        # Верификация подписи
        if hk_type == "ssh-ed25519":
            ok_sig = Ed25519.verify(hk_pub, H, sig_bytes)
        elif hk_type == "ssh-rsa":
            e_int = int.from_bytes(rsa_e_b, "big")
            n_int = int.from_bytes(rsa_n_b, "big")
            rsa_pub = RSAKey.from_components(n_int, e_int)
            ok_sig = rsa_pub.verify(H, sig_bytes, algo_name=sig_type)
        else:
            raise SSHHostKeyError(f"unsupported host key: {hk_type}")

        if not ok_sig:
            raise SSHHostKeyError("host key signature FAILED")

        self.session_id = H
        self.host_key_blob = K_S
        self.host_fp = "SHA256:" + base64.b64encode(
                           hashlib.sha256(K_S).digest()).decode().rstrip("=")

        # known_hosts
        if self.known_hosts_path is not None:
            entries = _kh_load(self.known_hosts_path)
            status = _kh_check(entries, self.host, self.port, hk_type, K_S)
            if status == "match":
                if self.verbose: print("       known_hosts    : match ✓")
            elif status == "mismatch":
                raise SSHHostKeyError(
                    f"REMOTE HOST IDENTIFICATION HAS CHANGED for {self.host}! "
                    f"Possible MITM. Key: {self.host_fp}")
            else:
                if self.strict:
                    raise SSHHostKeyError(
                        f"unknown host {self.host}:{self.port} (fp={self.host_fp}); "
                        f"use strict=False for TOFU")
                _kh_append(self.known_hosts_path, self.host, self.port, hk_type, K_S)
                if self.verbose: print("       known_hosts    : new → added")

        if self.verbose:
            print(f"       host key fp    : {self.host_fp}")
            print(f"       signature OK   : ✓")

        enc = self.algorithms["enc_c2s"]
        if enc == "chacha20-poly1305@openssh.com":
            key_c2s = derive_key(K_ser, H, H, b"C", 64)
            key_s2c = derive_key(K_ser, H, H, b"D", 64)
            iv_c2s = iv_s2c = None
        else:
            iv_c2s  = derive_key(K_ser, H, H, b"A", 12)
            iv_s2c  = derive_key(K_ser, H, H, b"B", 12)
            key_c2s = derive_key(K_ser, H, H, b"C", 32)
            key_s2c = derive_key(K_ser, H, H, b"D", 32)

        self.transport.send(bytes([MSG_NEWKEYS]))
        if self.verbose: print("       -> NEWKEYS")
        self.transport.recv()
        if self.verbose: print("       <- NEWKEYS")

        self.transport.packetizer.seq_send = 0
        self.transport.packetizer.seq_recv = 0
        self.transport.packetizer.enable_encryption(
            enc, key_c2s, key_s2c, iv_c2s, iv_s2c)
        if self.verbose: print("       [encryption ON]")

    def _compute_H(self, K_S, Q_C_bytes, Q_S_bytes, K_ser):
        """Вычислить H для exchange hash."""
        h = hashlib.sha256()
        h.update(_ssh_string(self.VERSION.encode()))
        h.update(_ssh_string(self.remote_version.encode()))
        h.update(_ssh_string(self.my_kexinit))
        h.update(_ssh_string(self.their_kexinit_raw))
        h.update(_ssh_string(K_S))
        h.update(_ssh_string(Q_C_bytes))
        h.update(_ssh_string(Q_S_bytes))
        h.update(K_ser)
        return h.digest(), K_ser

    def _verify_rsa_hostkey(self, H, hk_pub, sig_bytes, sig_type):
        e_b, o2 = read_string(hk_pub, 0)
        n_b, o2 = read_string(hk_pub, o2)
        e_int = int.from_bytes(e_b, "big")
        n_int = int.from_bytes(n_b, "big")
        rsa_pub = RSAKey.from_components(n_int, e_int)
        return rsa_pub.verify(H, sig_bytes, algo_name=sig_type)

        sig_type, o = read_string(sig_b, 0)
        sig_bytes, o = read_string(sig_b, o)
        hk_type, o = read_string(K_S, 0)
        hk_type = hk_type.decode()

        if hk_type == "ssh-ed25519":
            hk_pub, o = read_string(K_S, o)
            rsa_e_b = rsa_n_b = None
        elif hk_type == "ssh-rsa":
            rsa_e_b, o = read_string(K_S, o)
            rsa_n_b, o = read_string(K_S, o)
            hk_pub = None
        else:
            raise SSHHostKeyError(f"unsupported host key type: {hk_type}")

        sig_type = sig_type.decode()
        self._check_kex_consistency(hk_type, sig_type, K_S)

        K_raw = X25519.scalarmult(eph_priv, Q_S)
        H, K_ser = compute_exchange_hash(self.VERSION, self.remote_version,
                                         self.my_kexinit, self.their_kexinit_raw,
                                         K_S, eph_pub, Q_S, K_raw)

        # Диспетчер верификации по типу host key
        if hk_type == "ssh-ed25519":
            ok_sig = Ed25519.verify(hk_pub, H, sig_bytes)
        elif hk_type == "ssh-rsa":
            e_int = int.from_bytes(rsa_e_b, "big")
            n_int = int.from_bytes(rsa_n_b, "big")
            rsa_pub = RSAKey.from_components(n_int, e_int)
            ok_sig = rsa_pub.verify(H, sig_bytes, algo_name=sig_type)
        else:
            raise SSHHostKeyError(f"unsupported host key type: {hk_type}")

        if not ok_sig:
            raise SSHHostKeyError("host key signature FAILED")

        self.session_id = H
        self.host_key_blob = K_S
        self.host_pub = hk_pub
        self.host_fp = "SHA256:" + base64.b64encode(
                           hashlib.sha256(K_S).digest()).decode().rstrip("=")

        if self.known_hosts_path is not None:
            entries = _kh_load(self.known_hosts_path)
            status = _kh_check(entries, self.host, self.port, hk_type, K_S)
            if status == "match":
                if self.verbose: print("       known_hosts    : match ✓")
            elif status == "mismatch":
                raise SSHHostKeyError(
                    f"REMOTE HOST IDENTIFICATION HAS CHANGED for {self.host}! "
                    f"Possible MITM. Key: {self.host_fp}")
            else:
                if self.strict:
                    raise SSHHostKeyError(
                        f"unknown host {self.host}:{self.port} (fp={self.host_fp}); "
                        f"use strict=False for TOFU")
                _kh_append(self.known_hosts_path, self.host, self.port, hk_type, K_S)
                if self.verbose: print("       known_hosts    : new → added")

        if self.verbose:
            print(f"       host key fp    : {self.host_fp}")
            print(f"       signature OK   : ✓")

        enc = self.algorithms["enc_c2s"]
        if enc == "chacha20-poly1305@openssh.com":
            key_c2s = derive_key(K_ser, H, H, b"C", 64)
            key_s2c = derive_key(K_ser, H, H, b"D", 64)
            iv_c2s = iv_s2c = None
        else:
            iv_c2s  = derive_key(K_ser, H, H, b"A", 12)
            iv_s2c  = derive_key(K_ser, H, H, b"B", 12)
            key_c2s = derive_key(K_ser, H, H, b"C", 32)
            key_s2c = derive_key(K_ser, H, H, b"D", 32)

        self.transport.send(bytes([MSG_NEWKEYS]))
        if self.verbose: print("       -> NEWKEYS")
        self.transport.recv()
        if self.verbose: print("       <- NEWKEYS")

        # Strict KEX: reset seq numbers after NEWKEYS
        self.transport.packetizer.seq_send = 0
        self.transport.packetizer.seq_recv = 0

        self.transport.packetizer.enable_encryption(
            enc, key_c2s, key_s2c, iv_c2s, iv_s2c)
        if self.verbose: print("       [encryption ON]")

    def _service_request(self, name):
        self.transport.send(bytes([MSG_SERVICE_REQUEST]) + _ssh_string(name.encode()))
        if self.verbose: print(f"       -> SERVICE_REQUEST({name})")
        while True:
            resp = self.transport.recv()
            if resp[0] == MSG_EXT_INFO: continue
            if resp[0] == MSG_SERVICE_ACCEPT:
                if self.verbose: print(f"       <- SERVICE_ACCEPT({name})")
                return
            raise SSHProtocolError(f"unexpected msg {resp[0]}")

    def _recv_userauth(self):
        while True:
            resp = self.transport.recv()
            if resp[0] == MSG_USERAUTH_BANNER:
                banner, _ = read_string(resp, 1)
                if self.verbose: print(f"       <- BANNER: {banner.decode(errors='replace')}")
                continue
            if resp[0] == MSG_EXT_INFO: continue
            return resp

    def authenticate(self, username, service="ssh-connection"):
        algo = self.pub.KEYTYPE
        pubkey_blob = self.pub.public_blob()
        probe = build_userauth_request(username, service, "publickey",
                                       algo, pubkey_blob, False)
        self.transport.send(probe)
        if self.verbose: print(f"       -> USERAUTH_REQUEST({username}, probe)")
        resp = self._recv_userauth()
        if resp[0] == MSG_USERAUTH_FAILURE:
            return False
        if resp[0] != MSG_USERAUTH_PK_OK:
            raise ValueError(f"expected PK_OK, got {resp[0]}")

        request = build_userauth_request(username, service, "publickey",
                                         algo, pubkey_blob, True)
        signed = sign_userauth(self.session_id, request, self.priv)
        self.transport.send(signed)
        if self.verbose: print(f"       -> USERAUTH_REQUEST({username}, signed)")

        while True:
            resp = self._recv_userauth()
            if resp[0] == MSG_USERAUTH_SUCCESS:
                if self.verbose: print("       <- USERAUTH_SUCCESS ✓")
                # ssh-connection активируется автоматически после userauth.
                # Дополнительный SERVICE_REQUEST не нужен (OpenSSH может
                # сразу прислать CHANNEL_OPEN).
                return True
            if resp[0] == MSG_USERAUTH_FAILURE:
                return False
            raise SSHProtocolError(f"unexpected msg {resp[0]}")

    def authenticate_password(self, username, password, service="ssh-connection"):
        request = build_userauth_password(username, service, password)
        self.transport.send(request)
        if self.verbose: print(f"       -> USERAUTH_REQUEST({username}, password)")
        while True:
            resp = self._recv_userauth()
            if resp[0] == MSG_USERAUTH_SUCCESS:
                if self.verbose: print("       <- USERAUTH_SUCCESS ✓")
                return True
            if resp[0] == MSG_USERAUTH_FAILURE:
                return False
            raise SSHProtocolError(f"unexpected msg {resp[0]}")

    # ---------- channels ----------
    def open_session(self, window=2*1024*1024, max_packet=32768):
        self.local_channel = 0
        payload = (bytes([MSG_CHANNEL_OPEN]) + _ssh_string(b"session")
                   + struct.pack(">I", self.local_channel)
                   + struct.pack(">I", window)
                   + struct.pack(">I", max_packet))
        self.transport.send(payload)
        if self.verbose: print("       -> CHANNEL_OPEN(session)")

        # Читаем до CHANNEL_OPEN_CONFIRMATION, отвечая на служебные пакеты.
        while True:
            resp = self.transport.recv()
            t = resp[0]

            if t == MSG_CHANNEL_OPEN_CONFIRMATION:
                off = 1 + 4  # skip recipient-channel
                sender = struct.unpack(">I", resp[off:off+4])[0]
                self.remote_channel = sender
                if self.verbose:
                    print(f"       <- CHANNEL_OPEN_CONFIRMATION(remote={sender})")
                return sender

            if t == MSG_GLOBAL_REQUEST:
                off = 1
                req_name, off = read_string(resp, off)
                want_reply = resp[off]
                if self.verbose:
                    print(f"       <- GLOBAL_REQUEST({req_name.decode(errors='replace')})")
                if want_reply:
                    self.transport.send(bytes([MSG_REQUEST_FAILURE]))
                continue

            if t in (MSG_EXT_INFO, MSG_DEBUG, MSG_IGNORE):
                continue

            if t == MSG_CHANNEL_OPEN:
                # Встречный channel-open — отказываем.
                off = 1
                ctype, off = read_string(resp, off)
                their_chan = struct.unpack(">I", resp[off:off+4])[0]
                if self.verbose:
                    print(f"       <- CHANNEL_OPEN({ctype.decode()}, sender={their_chan}) — отказ")
                fail = (bytes([MSG_CHANNEL_OPEN_FAILURE])
                        + struct.pack(">I", their_chan)
                        + struct.pack(">I", 1)
                        + _ssh_string(b"not supported")
                        + _ssh_string(b""))
                self.transport.send(fail)
                continue

            raise SSHChannelError(f"channel open failed: msg {t}")


    def request_pty(self, term="xterm-256color", cols=80, rows=24,
                    width_px=0, height_px=0, modes=b""):
        payload = (bytes([MSG_CHANNEL_REQUEST])
                   + struct.pack(">I", self.remote_channel)
                   + _ssh_string(b"pty-req") + b"\x01"
                   + _ssh_string(term.encode())
                   + struct.pack(">I", cols) + struct.pack(">I", rows)
                   + struct.pack(">I", width_px) + struct.pack(">I", height_px)
                   + _ssh_string(modes))
        self.transport.send(payload)
        if self.verbose: print(f"       -> CHANNEL_REQUEST(pty-req, {term}, {cols}x{rows})")
        resp = self._recv_channel_reply((MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE))
        if resp[0] != MSG_CHANNEL_SUCCESS:
            raise SSHChannelError(f"pty-req rejected: msg {resp[0]}")
        if self.verbose: print("       <- CHANNEL_SUCCESS")


    def _recv_channel_reply(self, expect_types, ignore_types=None):
        """Читает пакеты до одного из expect_types. Игнорирует служебные."""
        if ignore_types is None:
            ignore_types = (MSG_CHANNEL_WINDOW_ADJUST, MSG_GLOBAL_REQUEST,
                            MSG_DEBUG, MSG_IGNORE, MSG_EXT_INFO)
        while True:
            resp = self.transport.recv()
            t = resp[0]
            if t in expect_types:
                return resp
            if t == MSG_CHANNEL_WINDOW_ADJUST:
                continue
            if t == MSG_GLOBAL_REQUEST:
                off = 1
                req_name, off = read_string(resp, off)
                want_reply = resp[off]
                if want_reply:
                    self.transport.send(bytes([MSG_REQUEST_FAILURE]))
                continue
            if t in (MSG_DEBUG, MSG_IGNORE, MSG_EXT_INFO):
                continue
            if t == MSG_CHANNEL_DATA or t == MSG_CHANNEL_EXTENDED_DATA:
                # пришёл до подтверждения — сохраняем как pending output? Пока просто пропустим.
                continue
            if t == MSG_CHANNEL_EOF:
                continue
            # Неожиданный тип — возвращаем как есть
            return resp

    def exec_command(self, command):
        if self.remote_channel is None: raise RuntimeError("no channel")
        payload = (bytes([MSG_CHANNEL_REQUEST])
                   + struct.pack(">I", self.remote_channel)
                   + _ssh_string(b"exec") + b"\x01"
                   + _ssh_string(command.encode()))
        self.transport.send(payload)
        if self.verbose: print(f"       -> CHANNEL_REQUEST(exec, {command!r})")
        resp = self._recv_channel_reply((MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE))
        if resp[0] != MSG_CHANNEL_SUCCESS:
            raise SSHChannelError(f"exec rejected: {resp[0]}")
        if self.verbose: print("       <- CHANNEL_SUCCESS")

        output = bytearray()
        exit_status = None
        while True:
            pkt = self.transport.recv()
            t = pkt[0]
            if t in (MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA):
                off = 1 + 4
                if t == MSG_CHANNEL_EXTENDED_DATA: off += 4
                data, off = read_string(pkt, off)
                output += data
            elif t == MSG_CHANNEL_REQUEST:
                off = 1 + 4
                req_type, off = read_string(pkt, off)
                off += 1
                if req_type == b"exit-status":
                    exit_status = struct.unpack(">I", pkt[off:off+4])[0]
            elif t == MSG_CHANNEL_EOF:
                pass
            elif t == MSG_CHANNEL_CLOSE:
                r = struct.unpack(">I", pkt[1:5])[0]
                self.transport.send(bytes([MSG_CHANNEL_CLOSE]) + struct.pack(">I", r))
                break
            elif t in (MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_SUCCESS,
                       MSG_CHANNEL_FAILURE, MSG_IGNORE, MSG_DEBUG):
                pass
            else:
                raise SSHProtocolError(f"unexpected msg {t}")
        return exit_status, bytes(output)

    def request_subsystem(self, name):
        """Запросить subsystem (например, 'sftp') на открытом session-канале."""
        if self.remote_channel is None:
            raise RuntimeError("no channel")
        payload = (bytes([MSG_CHANNEL_REQUEST])
                   + struct.pack(">I", self.remote_channel)
                   + _ssh_string(b"subsystem") + b"\x01"
                   + _ssh_string(name.encode()))
        self.transport.send(payload)
        if self.verbose:
            print(f"       -> CHANNEL_REQUEST(subsystem, {name!r})")
        resp = self._recv_channel_reply((MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE))
        if resp[0] != MSG_CHANNEL_SUCCESS:
            raise SSHChannelError(f"subsystem {name!r} rejected: {resp[0]}")
        if self.verbose:
            print("       <- CHANNEL_SUCCESS")

    def invoke_shell(self):
        payload = (bytes([MSG_CHANNEL_REQUEST])
                   + struct.pack(">I", self.remote_channel)
                   + _ssh_string(b"shell") + b"\x01")
        self.transport.send(payload)
        if self.verbose: print("       -> CHANNEL_REQUEST(shell)")
        resp = self._recv_channel_reply((MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE))
        if resp[0] != MSG_CHANNEL_SUCCESS:
            raise SSHChannelError(f"shell rejected: {resp[0]}")
        if self.verbose: print("       <- CHANNEL_SUCCESS")

    # ---------- интерактивный shell ----------
    def openshell(self, user=None, host=None, port=None, term="xterm-256color",
                  cols=80, rows=24):
        """
        Интерактивный shell как в настоящем ssh:
        клиент ничего не печатает от себя, только транслирует то,
        что приходит от сервера. Bash сам рисует свой prompt.
        """
        import sys as _sys
        host = host or self.host
        port = port or self.port
        if user is None:
            user = _get_username()

        self.open_session()
        self.request_pty(term=term, cols=cols, rows=rows)
        self.invoke_shell()

        # Дать bash инициализироваться и показать первый prompt.
        # НИЧЕГО не очищаем — demo-вывод и banner должны остаться.
        import time as _t
        _t.sleep(0.35)
        _initial = self._drain_output(idle=0.35, total=2.0)
        if _initial:
            sys.stdout.buffer.write(_initial)
            sys.stdout.buffer.flush()

        # termios raw — для полной прозрачности
        use_raw = False
        stdin_fd = None
        old_attrs = None
        try:
            import termios, tty
            stdin_fd = _sys.stdin.fileno()
            if os.isatty(stdin_fd):
                old_attrs = termios.tcgetattr(stdin_fd)
                tty.setraw(stdin_fd)
                use_raw = True
        except Exception:
            use_raw = False

        import threading
        stop = threading.Event()

        def pump_stdin():
            try:
                while not stop.is_set():
                    r, _, _ = select.select([stdin_fd], [], [], 0.05)
                    if stdin_fd not in r:
                        continue
                    data = os.read(stdin_fd, 1024)
                    if not data:
                        break
                    self._send_shell(data)
            except Exception:
                pass

        try:
            if use_raw:
                # PTY-режим — как обычный ssh
                th = threading.Thread(target=pump_stdin, daemon=True)
                th.start()
                while not stop.is_set():
                    try:
                        pkt = self.transport.recv()
                    except (EOFError, OSError):
                        break
                    t = pkt[0]
                    if t in (MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA):
                        off = 1 + 4
                        if t == MSG_CHANNEL_EXTENDED_DATA:
                            off += 4
                        data, off = read_string(pkt, off)
                        _sys.stdout.buffer.write(data)
                        _sys.stdout.buffer.flush()
                    elif t == MSG_CHANNEL_EOF:
                        pass
                    elif t == MSG_CHANNEL_CLOSE:
                        r = struct.unpack(">I", pkt[1:5])[0]
                        try:
                            self.transport.send(bytes([MSG_CHANNEL_CLOSE])
                                                + struct.pack(">I", r))
                        except Exception:
                            pass
                        break
                    elif t in (MSG_CHANNEL_WINDOW_ADJUST, MSG_IGNORE,
                               MSG_DEBUG, MSG_CHANNEL_REQUEST,
                               MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE):
                        continue
            else:
                # PIPE-fallback: bash не echo'ит, prompt не рисует.
                # Используем наш минимальный prompt, чтобы пользователь видел ввод.
                while True:
                    try:
                        line = input("ssh> ")
                    except (EOFError, KeyboardInterrupt):
                        _sys.stdout.write("\n")
                        line = "exit"
                    stripped = line.strip()
                    if stripped in ("exit", "quit", "logout"):
                        self._send_shell(b"exit\n")
                        time.sleep(0.3)
                        self._drain_output(idle=0.3, total=2.0)
                        _sys.stdout.write("logout\n")
                        _sys.stdout.flush()
                        break
                    if not stripped:
                        continue
                    marker = _detect_heredoc(line)
                    if marker:
                        block = [line]
                        while True:
                            try:
                                nxt = input("> ")
                            except (EOFError, KeyboardInterrupt):
                                _sys.stdout.write("\n")
                                break
                            block.append(nxt)
                            if nxt.strip() == marker:
                                break
                        data = ("\n".join(block) + "\n").encode()
                        self._send_shell(data)
                        out = self._drain_output(idle=0.5, total=120.0)
                        if out:
                            _sys.stdout.write(out.decode(errors="replace"))
                            _sys.stdout.flush()
                        continue
                    self._send_shell((line + "\n").encode())
                    out = self._drain_output(idle=0.25, total=15.0)
                    if out:
                        _sys.stdout.write(out.decode(errors="replace"))
                        _sys.stdout.flush()
        finally:
            stop.set()
            if use_raw and old_attrs is not None:
                try:
                    import termios
                    termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
                except Exception:
                    pass

        self.close_channel()

    def _detect_pty_mode(self):
        """true если pty (есть эхо от bash), false — pipe."""
        marker = "__PTY_DETECT_9f1__"
        self._send_shell((f"echo {marker}\n").encode())
        out = self._drain_output(idle=0.35, total=2.0)
        text = out.decode(errors="replace") if out else ""
        return text.count(marker) >= 2

    def _detect_pty_mode(self):
        """Проверяет pty: echo возвращает команду дважды."""
        marker = "__PTY_DETECT_9f1__"
        self._send_shell((f"echo {marker}\n").encode())
        out = self._drain_output(idle=0.35, total=2.0)
        text = out.decode(errors="replace") if out else ""
        return text.count(marker) >= 2

    def _detect_pty_mode(self):
        """true если shell работает в pty (echo есть), false — если pipe."""
        # Отправим пустой echo и посмотрим, вернётся ли он
        marker = "__PTY_DETECT_9f1__"
        self._send_shell((f"echo {marker}\n").encode())
        out = self._drain_output(idle=0.35, total=2.0)
        text = out.decode(errors="replace") if out else ""
        # В pty bash echo'ит и саму команду, поэтому marker попадёт 2 раза
        # В pipe — только один (только вывод)
        return text.count(marker) >= 2

    def _send_shell(self, data: bytes):
        if self.remote_channel is None:
            raise RuntimeError("no channel")
        self.transport.send(bytes([MSG_CHANNEL_DATA])
                            + struct.pack(">I", self.remote_channel)
                            + _ssh_string(data))

    def _drain_output(self, idle=0.25, total=15.0):
        """Читает CHANNEL_DATA пока идёт поток."""
        buf = bytearray()
        last = time.time()
        start = time.time()
        old_timeout = self.sock.gettimeout()

        try:
            while time.time() - last < idle and time.time() - start < total:
                self.sock.settimeout(idle)
                try:
                    pkt = self.transport.recv()
                except (socket.timeout, TimeoutError):
                    break
                except (EOFError, OSError):
                    break

                t = pkt[0]
                if t in (MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA):
                    off = 1 + 4
                    if t == MSG_CHANNEL_EXTENDED_DATA: off += 4
                    data, off = read_string(pkt, off)
                    buf += data
                    last = time.time()
                elif t in (MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE):
                    break
                elif t in (MSG_CHANNEL_WINDOW_ADJUST, MSG_IGNORE,
                           MSG_DEBUG, MSG_CHANNEL_REQUEST,
                           MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE):
                    continue
                else:
                    break
        finally:
            self.sock.settimeout(old_timeout)
        return bytes(buf)

    def close_channel(self):
        self.remote_channel = None

    def disconnect(self, reason=DISC_BY_APPLICATION, description="bye"):
        try:
            self.transport.send(build_disconnect(reason, description))
        except Exception:
            pass
        self.close()

    def close(self):
        try: self.sock.close()
        except Exception: pass

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    def __repr__(self):
        return f"<SSH {self.host}:{self.port} host_fp={self.host_fp}>"


# ═══════════════════════════════════════════════════════════════════════
# 11. Server
# ═══════════════════════════════════════════════════════════════════════
ALLOWED_COMMANDS = {"echo", "whoami", "date", "uname", "pwd", "id", "ls", "cat"}


class _Session:
    """Состояние одного клиента."""
    def __init__(self, transport):
        self.t = transport
        self.remote_channel = None
        self.shell_fd = None
        self.shell_proc = None
        self.shell_stdin = None
        self.shell_kind = None
        self.pty_info = None
        self.sftp = None
        self._shell_write_lock = threading.Lock()

    def send_channel_data(self, data: bytes):
        if self.remote_channel is None: return
        with self._shell_write_lock:
            try:
                self.t.send(bytes([MSG_CHANNEL_DATA])
                            + struct.pack(">I", self.remote_channel)
                            + _ssh_string(data))
            except Exception:
                pass

    def send_channel_eof_close(self):
        if self.remote_channel is None: return
        try:
            self.t.send(bytes([MSG_CHANNEL_EOF]) + struct.pack(">I", self.remote_channel))
            self.t.send(bytes([MSG_CHANNEL_CLOSE]) + struct.pack(">I", self.remote_channel))
        except Exception:
            pass

    def kill_shell(self):
        if self.shell_proc is not None:
            try: self.shell_proc.terminate()
            except Exception: pass
            self.shell_proc = None
        if self.shell_fd is not None:
            try: os.close(self.shell_fd)
            except Exception: pass
            self.shell_fd = None
        if self.shell_stdin is not None:
            try: self.shell_stdin.close()
            except Exception: pass
            self.shell_stdin = None
        self.shell_kind = None




# ═══════════════════════════════════════════════════════════════════════
# SFTP v3 (draft-ietf-secsh-filexfer-02) — минимальный сервер
# ═══════════════════════════════════════════════════════════════════════
# Типы пакетов
SFTP_INIT        = 1
SFTP_VERSION     = 2
SFTP_OPEN        = 3
SFTP_CLOSE       = 4
SFTP_READ        = 5
SFTP_WRITE       = 6
SFTP_LSTAT       = 7
SFTP_FSTAT       = 8
SFTP_SETSTAT     = 9
SFTP_FSETSTAT    = 10
SFTP_OPENDIR     = 11
SFTP_READDIR     = 12
SFTP_REMOVE      = 13
SFTP_MKDIR       = 14
SFTP_RMDIR       = 15
SFTP_REALPATH    = 16
SFTP_STAT        = 17
SFTP_RENAME      = 18
SFTP_READLINK    = 19
SFTP_SYMLINK     = 20

# Open flags (SSH_FXF_*)
SSH_FXF_READ     = 0x00000001
SSH_FXF_WRITE    = 0x00000002
SSH_FXF_APPEND   = 0x00000004
SSH_FXF_CREAT    = 0x00000008
SSH_FXF_TRUNC    = 0x00000010
SSH_FXF_EXCL     = 0x00000020

SFTP_STATUS      = 101
SFTP_HANDLE      = 102
SFTP_DATA        = 103
SFTP_NAME        = 104
SFTP_ATTRS       = 105

# Статусы
FX_OK            = 0
FX_EOF           = 1
FX_NO_SUCH_FILE  = 2
FX_PERMISSION    = 3
FX_FAILURE       = 4
FX_BAD_MESSAGE   = 5
FX_NO_CONNECTION = 6
FX_CONN_LOST     = 7
FX_OP_UNSUPPORTED= 8

# Атрибуты (flags)
SSH_FILEXFER_ATTR_SIZE        = 0x00000001
SSH_FILEXFER_ATTR_UIDGID      = 0x00000002
SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH_FILEXFER_ATTR_ACMODTIME   = 0x00000008
SSH_FILEXFER_ATTR_EXTENDED    = 0x80000000


def _sftp_u32(n):  return struct.pack(">I", n & 0xFFFFFFFF)
def _sftp_u64(n):  return struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)
def _sftp_str(b):  return _sftp_u32(len(b)) + b


def _sftp_attrs(path, follow=True):
    """Сформировать атрибуты для stat/lstat."""
    try:
        st = os.stat(path) if follow else os.lstat(path)
    except FileNotFoundError:
        return None
    flags = (SSH_FILEXFER_ATTR_SIZE
             | SSH_FILEXFER_ATTR_UIDGID
             | SSH_FILEXFER_ATTR_PERMISSIONS
             | SSH_FILEXFER_ATTR_ACMODTIME)
    out = _sftp_u32(flags)
    out += _sftp_u64(st.st_size)
    out += _sftp_u32(st.st_uid) + _sftp_u32(st.st_gid)
    out += _sftp_u32(st.st_mode)
    out += _sftp_u32(int(st.st_atime)) + _sftp_u32(int(st.st_mtime))
    return out


class SFTPSession:
    """Одна SFTP-сессия. Парсит пакеты из CHANNEL_DATA и отвечает."""

    def __init__(self, transport, remote_channel, root, log=None):
        self.t = transport
        self.chan = remote_channel
        self.root = os.path.realpath(os.path.expanduser(root))
        self.buf = bytearray()
        self.handles = {}      # id -> dict(kind, obj, path)
        self.next_handle = 1
        self._log = log or (lambda msg: None)

    # ─── ввод/вывод ───────────────────────────────────────
    def feed(self, data: bytes):
        self.buf += data
        while len(self.buf) >= 4:
            plen = struct.unpack(">I", self.buf[:4])[0]
            if plen < 1 or plen > 1024*1024:
                # битый пакет — сбрасываем буфер
                self.buf.clear()
                return
            if len(self.buf) < 4 + plen:
                break
            pkt = bytes(self.buf[4:4+plen])
            del self.buf[:4+plen]
            try:
                self._dispatch(pkt)
            except Exception as e:
                self._log(f"[sftp] exception: {type(e).__name__}: {e}")
                import traceback
                if self._log:
                    traceback.print_exc()

    def send(self, payload: bytes):
        packet = _sftp_u32(len(payload)) + payload
        self.t.send(bytes([MSG_CHANNEL_DATA])
                    + struct.pack(">I", self.chan)
                    + _ssh_string(packet))

    # ─── утилиты ──────────────────────────────────────────
    def _resolve(self, path: str):
        """Привести путь к абсолютному в пределах root."""
        if not path:
            path = "."
        # Нормализуем
        if path.startswith("/"):
            rel = path[1:]
        else:
            rel = path
        # Склеиваем с root, нормализуем, отрезаем root
        full = os.path.normpath(os.path.join(self.root, rel))
        # Безопасность: full должен быть внутри root
        real = os.path.realpath(full)
        if not (real == self.root or real.startswith(self.root + os.sep)):
            return None
        return full

    def _status(self, req_id, code, message=b""):
        out = bytes([SFTP_STATUS]) + _sftp_u32(req_id) + _sftp_u32(code)
        out += _sftp_str(message)
        out += _sftp_str(b"")  # language tag
        self.send(out)

    def _alloc_handle(self, kind, obj, path):
        hid = self.next_handle
        self.next_handle += 1
        self.handles[hid] = {"kind": kind, "obj": obj, "path": path}
        return hid

    def _handle_bytes(self, hid):
        return str(hid).encode()

    def _lookup_handle(self, raw):
        try:
            hid = int(raw.decode())
        except Exception:
            return None
        return self.handles.get(hid)

    # ─── диспетчер ────────────────────────────────────────
    def _dispatch(self, pkt):
        t = pkt[0]
        if t == SFTP_INIT:
            self._handle_init(pkt)
        elif t == SFTP_REALPATH:
            self._handle_realpath(pkt)
        elif t == SFTP_STAT:
            self._handle_stat(pkt, follow=True)
        elif t == SFTP_LSTAT:
            self._handle_stat(pkt, follow=False)
        elif t == SFTP_OPENDIR:
            self._handle_opendir(pkt)
        elif t == SFTP_READDIR:
            self._handle_readdir(pkt)
        elif t == SFTP_CLOSE:
            self._handle_close(pkt)
        elif t == SFTP_OPEN:
            self._handle_open(pkt)
        elif t == SFTP_READ:
            self._handle_read(pkt)
        elif t == SFTP_WRITE:
            self._handle_write(pkt)
        elif t == SFTP_FSTAT:
            self._handle_fstat(pkt)
        elif t == SFTP_FSETSTAT:
            self._handle_fsetstat(pkt)
        elif t == SFTP_MKDIR:
            self._handle_mkdir(pkt)
        elif t == SFTP_RMDIR:
            self._handle_rmdir(pkt)
        elif t == SFTP_REMOVE:
            self._handle_remove(pkt)
        elif t == SFTP_RENAME:
            self._handle_rename(pkt)
        elif t == SFTP_READLINK:
            self._handle_readlink(pkt)
        elif t == SFTP_SYMLINK:
            self._handle_symlink(pkt)
        elif t == SFTP_SETSTAT:
            self._handle_setstat(pkt)
        else:
            self._log(f"[sftp] unsupported: type={t}")
            req_id = struct.unpack(">I", pkt[1:5])[0] if len(pkt) >= 5 else 0
            self._status(req_id, FX_OP_UNSUPPORTED)

    # ─── обработчики ──────────────────────────────────────
    def _handle_init(self, pkt):
        version = struct.unpack(">I", pkt[1:5])[0]
        self._log(f"[sftp] INIT version={version}")
        # Отвечаем VERSION=3 без расширений
        self.send(bytes([SFTP_VERSION]) + struct.pack(">I", 3))

    def _handle_realpath(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        # Возвращаем путь относительно root, с ведущим "/"
        rel = os.path.relpath(full, self.root)
        if rel == ".":
            display = "/"
        else:
            display = "/" + rel
        # NAME: count=1, filename, longname, attrs
        out = bytes([SFTP_NAME]) + _sftp_u32(req_id) + _sftp_u32(1)
        out += _sftp_str(display.encode())
        out += _sftp_str(display.encode())  # longname
        attrs = _sftp_attrs(full, follow=False)
        if attrs is None:
            attrs = _sftp_u32(0)
        out += attrs
        self.send(out)

    def _handle_stat(self, pkt, follow=True):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        attrs = _sftp_attrs(full, follow=follow)
        if attrs is None:
            self._status(req_id, FX_NO_SUCH_FILE, b"no such file")
            return
        self.send(bytes([SFTP_ATTRS]) + _sftp_u32(req_id) + attrs)

    def _handle_opendir(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        if not os.path.isdir(full):
            self._status(req_id, FX_NO_SUCH_FILE, b"not a directory")
            return
        try:
            entries = sorted(os.listdir(full))
        except PermissionError:
            self._status(req_id, FX_PERMISSION, b"permission denied")
            return
        except OSError:
            self._status(req_id, FX_FAILURE, b"opendir failed")
            return
        hid = self._alloc_handle("dir", entries, full)
        self.send(bytes([SFTP_HANDLE]) + _sftp_u32(req_id)
                  + _sftp_str(self._handle_bytes(hid)))

    def _handle_readdir(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        handle, off = read_string(pkt, off)
        h = self._lookup_handle(handle)
        if h is None or h["kind"] != "dir":
            self._status(req_id, FX_FAILURE, b"invalid handle")
            return
        entries = h["obj"]
        if not entries:
            self._status(req_id, FX_EOF, b"")
            return
        # Отдаём всё сразу
        out = bytes([SFTP_NAME]) + _sftp_u32(req_id) + _sftp_u32(len(entries))
        for name in entries:
            if name in (".", ".."):
                continue
            full = os.path.join(h["path"], name)
            attrs = _sftp_attrs(full, follow=False)
            if attrs is None:
                continue
            out += _sftp_str(name.encode())
            out += _sftp_str(name.encode())  # longname — упрощённо
            out += attrs
        h["obj"] = []   # больше нет
        self.send(out)

    def _handle_open(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        pflags = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
        # attrs (для O_CREAT) — читаем, но игнорируем
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return

        flags = 0
        if pflags & SSH_FXF_READ and not (pflags & SSH_FXF_WRITE):
            flags |= os.O_RDONLY
        elif pflags & SSH_FXF_WRITE and not (pflags & SSH_FXF_READ):
            flags |= os.O_WRONLY
        else:
            flags |= os.O_RDWR
        if pflags & SSH_FXF_APPEND: flags |= os.O_APPEND
        if pflags & SSH_FXF_CREAT:  flags |= os.O_CREAT
        if pflags & SSH_FXF_TRUNC:  flags |= os.O_TRUNC
        if pflags & SSH_FXF_EXCL:   flags |= os.O_EXCL

        try:
            fd = os.open(full, flags, 0o644)
        except FileNotFoundError:
            self._status(req_id, FX_NO_SUCH_FILE, b"no such file")
            return
        except FileExistsError:
            self._status(req_id, FX_FAILURE, b"file exists")
            return
        except PermissionError:
            self._status(req_id, FX_PERMISSION, b"permission denied")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        hid = self._alloc_handle("file", fd, full)
        self.send(bytes([SFTP_HANDLE]) + _sftp_u32(req_id)
                  + _sftp_str(self._handle_bytes(hid)))

    def _handle_read(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        handle, off = read_string(pkt, off)
        offset = struct.unpack(">Q", pkt[off:off+8])[0]; off += 8
        length = struct.unpack(">I", pkt[off:off+4])[0]; off += 4

        h = self._lookup_handle(handle)
        if h is None or h["kind"] != "file":
            self._status(req_id, FX_FAILURE, b"invalid handle")
            return
        fd = h["obj"]
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, length)
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        if not data:
            self._status(req_id, FX_EOF, b"")
            return
        self.send(bytes([SFTP_DATA]) + _sftp_u32(req_id) + _sftp_str(data))

    def _handle_write(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        handle, off = read_string(pkt, off)
        offset = struct.unpack(">Q", pkt[off:off+8])[0]; off += 8
        data, off = read_string(pkt, off)

        h = self._lookup_handle(handle)
        if h is None or h["kind"] != "file":
            self._status(req_id, FX_FAILURE, b"invalid handle")
            return
        fd = h["obj"]
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            os.write(fd, data)
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        self._status(req_id, FX_OK)

    def _handle_fstat(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        handle, off = read_string(pkt, off)
        h = self._lookup_handle(handle)
        if h is None:
            self._status(req_id, FX_FAILURE, b"invalid handle")
            return
        if h["kind"] == "file":
            try:
                st = os.fstat(h["obj"])
            except OSError as e:
                self._status(req_id, FX_FAILURE, str(e).encode())
                return
            flags = (SSH_FILEXFER_ATTR_SIZE
                     | SSH_FILEXFER_ATTR_UIDGID
                     | SSH_FILEXFER_ATTR_PERMISSIONS
                     | SSH_FILEXFER_ATTR_ACMODTIME)
            attrs = _sftp_u32(flags)
            attrs += _sftp_u64(st.st_size)
            attrs += _sftp_u32(st.st_uid) + _sftp_u32(st.st_gid)
            attrs += _sftp_u32(st.st_mode)
            attrs += _sftp_u32(int(st.st_atime)) + _sftp_u32(int(st.st_mtime))
        elif h["kind"] == "dir":
            attrs = _sftp_attrs(h["path"], follow=False) or _sftp_u32(0)
        else:
            attrs = _sftp_u32(0)
        self.send(bytes([SFTP_ATTRS]) + _sftp_u32(req_id) + attrs)

    def _handle_fsetstat(self, pkt):
        # Минимально: не поддерживаем изменения
        req_id = struct.unpack(">I", pkt[1:5])[0]
        self._status(req_id, FX_OP_UNSUPPORTED, b"fsetstat not supported")

    def _handle_mkdir(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        # attrs (permissions) — читаем
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        try:
            os.mkdir(full, 0o755)
        except FileExistsError:
            self._status(req_id, FX_FAILURE, b"already exists")
            return
        except PermissionError:
            self._status(req_id, FX_PERMISSION, b"permission denied")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        self._status(req_id, FX_OK)

    def _handle_rmdir(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        try:
            os.rmdir(full)
        except FileNotFoundError:
            self._status(req_id, FX_NO_SUCH_FILE, b"no such dir")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        self._status(req_id, FX_OK)

    def _handle_remove(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        try:
            os.unlink(full)
        except FileNotFoundError:
            self._status(req_id, FX_NO_SUCH_FILE, b"no such file")
            return
        except IsADirectoryError:
            self._status(req_id, FX_FAILURE, b"is a directory")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        self._status(req_id, FX_OK)

    def _handle_rename(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        old_path, off = read_string(pkt, off)
        new_path, off = read_string(pkt, off)
        old_full = self._resolve(old_path.decode(errors="replace"))
        new_full = self._resolve(new_path.decode(errors="replace"))
        if old_full is None or new_full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        try:
            os.rename(old_full, new_full)
        except FileNotFoundError:
            self._status(req_id, FX_NO_SUCH_FILE, b"no such file")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        self._status(req_id, FX_OK)

    def _handle_readlink(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        path, off = read_string(pkt, off)
        path = path.decode(errors="replace")
        full = self._resolve(path)
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        try:
            target = os.readlink(full)
        except FileNotFoundError:
            self._status(req_id, FX_NO_SUCH_FILE, b"no such file")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        out = bytes([SFTP_NAME]) + _sftp_u32(req_id) + _sftp_u32(1)
        out += _sftp_str(target.encode())
        out += _sftp_str(target.encode())
        attrs = _sftp_attrs(full, follow=False)
        if attrs is None:
            attrs = _sftp_u32(0)
        out += attrs
        self.send(out)

    def _handle_symlink(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        target, off = read_string(pkt, off)
        linkpath, off = read_string(pkt, off)
        target = target.decode(errors="replace")
        full = self._resolve(linkpath.decode(errors="replace"))
        if full is None:
            self._status(req_id, FX_PERMISSION, b"path outside root")
            return
        try:
            os.symlink(target, full)
        except FileExistsError:
            self._status(req_id, FX_FAILURE, b"exists")
            return
        except OSError as e:
            self._status(req_id, FX_FAILURE, str(e).encode())
            return
        self._status(req_id, FX_OK)

    def _handle_setstat(self, pkt):
        # Минимально: не поддерживаем
        req_id = struct.unpack(">I", pkt[1:5])[0]
        self._status(req_id, FX_OP_UNSUPPORTED, b"setstat not supported")

    def _handle_close(self, pkt):
        req_id = struct.unpack(">I", pkt[1:5])[0]
        off = 5
        handle, off = read_string(pkt, off)
        try:
            hid = int(handle.decode())
        except Exception:
            self._status(req_id, FX_FAILURE, b"bad handle")
            return
        h = self.handles.pop(hid, None)
        if h is not None and h["kind"] == "file":
            try:
                os.close(h["obj"])
            except OSError:
                pass
        self._status(req_id, FX_OK)



# ═══════════════════════════════════════════════════════════════════════
# SFTP v3 клиент
# ═══════════════════════════════════════════════════════════════════════
class SFTPClient:
    """SFTP v3 клиент поверх SSH-канала.

    Использование:
        sftp = SFTPClient(ssh)   # ssh — уже аутентифицированный SSH
        sftp.open_session()      # открыть session + subsystem sftp
        for name in sftp.listdir("/"):
            print(name)
        sftp.run_cli()
    """

    def __init__(self, ssh):
        self.ssh = ssh
        self.buf = bytearray()
        self.next_id = 1
        self.handles = {}       # id -> {"kind", "path"} для dir/file
        self.version = None

    # ─── низкоуровневый обмен ─────────────────────────────
    def _send(self, pkt_type, body_bytes):
        req_id = self.next_id
        self.next_id += 1
        payload = bytes([pkt_type]) + struct.pack(">I", req_id) + body_bytes
        packet = struct.pack(">I", len(payload)) + payload
        self.ssh._send_shell(packet)
        return req_id

    def _send_no_id(self, pkt_type, body_bytes):
        payload = bytes([pkt_type]) + body_bytes
        packet = struct.pack(">I", len(payload)) + payload
        self.ssh._send_shell(packet)

    def _read_channel(self, timeout=10.0):
        """Прочитать один CHANNEL_DATA и вернуть payload SFTP-пакета.
        Возвращает None при EOF/close."""
        import select
        pkt = self.ssh.transport.recv()
        t = pkt[0]
        if t in (MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA):
            off = 1 + 4
            if t == MSG_CHANNEL_EXTENDED_DATA:
                off += 4
            data, off = read_string(pkt, off)
            return data
        if t == MSG_CHANNEL_EOF:
            return None
        if t == MSG_CHANNEL_CLOSE:
            return None
        if t in (MSG_CHANNEL_WINDOW_ADJUST, MSG_GLOBAL_REQUEST,
                 MSG_DEBUG, MSG_IGNORE, MSG_EXT_INFO, MSG_CHANNEL_REQUEST):
            return b""
        raise SSHChannelError(f"unexpected msg in SFTP channel: {t}")

    def _read_sftp_packet(self, timeout=10.0):
        """Собрать один полный SFTP-пакет из канала."""
        while True:
            # Уже есть в буфере?
            if len(self.buf) >= 4:
                plen = struct.unpack(">I", self.buf[:4])[0]
                if len(self.buf) >= 4 + plen:
                    pkt = bytes(self.buf[4:4+plen])
                    del self.buf[:4+plen]
                    return pkt
            chunk = self._read_channel(timeout=timeout)
            if chunk is None:
                return None
            if chunk:
                self.buf += chunk

    def _wait_response(self, req_id):
        """Читать SFTP-пакеты до ответа с нужным req_id."""
        while True:
            pkt = self._read_sftp_packet()
            if pkt is None:
                raise SSHChannelError("SFTP channel closed")
            t = pkt[0]
            if t == SFTP_VERSION:
                self.version = struct.unpack(">I", pkt[1:5])[0]
                return ("VERSION", self.version)
            if t == SFTP_STATUS:
                rid = struct.unpack(">I", pkt[1:5])[0]
                code = struct.unpack(">I", pkt[5:9])[0]
                off = 9
                msg, off = read_string(pkt, off)
                lang, off = read_string(pkt, off)
                if rid != req_id and req_id != 0:
                    continue
                return ("STATUS", code, msg.decode(errors="replace"))
            if t == SFTP_HANDLE:
                rid = struct.unpack(">I", pkt[1:5])[0]
                if rid != req_id:
                    continue
                h, _ = read_string(pkt, 5)
                return ("HANDLE", h)
            if t == SFTP_DATA:
                rid = struct.unpack(">I", pkt[1:5])[0]
                if rid != req_id:
                    continue
                d, _ = read_string(pkt, 5)
                return ("DATA", d)
            if t == SFTP_ATTRS:
                rid = struct.unpack(">I", pkt[1:5])[0]
                if rid != req_id:
                    continue
                return ("ATTRS", pkt[5:])
            if t == SFTP_NAME:
                rid = struct.unpack(">I", pkt[1:5])[0]
                if rid != req_id:
                    continue
                count = struct.unpack(">I", pkt[5:9])[0]
                off = 9
                names = []
                for _ in range(count):
                    fname, off = read_string(pkt, off)
                    lname, off = read_string(pkt, off)
                    attrs, off = self._parse_attrs(pkt, off)
                    names.append((fname.decode(errors="replace"),
                                  lname.decode(errors="replace"),
                                  attrs))
                return ("NAME", names)
            # Неизвестный тип — пропускаем
            # (OpenSSH может прислать EXTENDED_REPLY — игнорируем)

    def _parse_attrs(self, buf, off):
        """Разобрать attrs в dict."""
        flags = struct.unpack(">I", buf[off:off+4])[0]; off += 4
        attrs = {"flags": flags}
        if flags & SSH_FILEXFER_ATTR_SIZE:
            attrs["size"] = struct.unpack(">Q", buf[off:off+8])[0]; off += 8
        if flags & SSH_FILEXFER_ATTR_UIDGID:
            attrs["uid"] = struct.unpack(">I", buf[off:off+4])[0]; off += 4
            attrs["gid"] = struct.unpack(">I", buf[off:off+4])[0]; off += 4
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS:
            attrs["mode"] = struct.unpack(">I", buf[off:off+4])[0]; off += 4
        if flags & SSH_FILEXFER_ATTR_ACMODTIME:
            attrs["atime"] = struct.unpack(">I", buf[off:off+4])[0]; off += 4
            attrs["mtime"] = struct.unpack(">I", buf[off:off+4])[0]; off += 4
        if flags & SSH_FILEXFER_ATTR_EXTENDED:
            count = struct.unpack(">I", buf[off:off+4])[0]; off += 4
            for _ in range(count):
                _, off = read_string(buf, off)
                _, off = read_string(buf, off)
        return attrs, off

    # ─── API ──────────────────────────────────────────────
    def open_session(self):
        """Открыть session-канал и запросить subsystem=sftp, потом INIT."""
        self.ssh.open_session()
        self.ssh.request_subsystem("sftp")
        # INIT
        self._send_no_id(SFTP_INIT, struct.pack(">I", 3))
        result = self._wait_response(0)
        if result[0] != "VERSION":
            raise SSHChannelError(f"expected VERSION, got {result}")
        self.version = result[1]
        return self.version

    def realpath(self, path="."):
        req_id = self._send(SFTP_REALPATH, _sftp_str(path.encode()))
        resp = self._wait_response(req_id)
        if resp[0] == "NAME":
            return resp[1][0][0]
        raise SSHChannelError(f"realpath failed: {resp}")

    def stat(self, path, follow=True):
        t = SFTP_STAT if follow else SFTP_LSTAT
        req_id = self._send(t, _sftp_str(path.encode()))
        resp = self._wait_response(req_id)
        if resp[0] == "ATTRS":
            attrs, _ = self._parse_attrs(resp[1], 0)
            return attrs
        raise SSHChannelError(f"stat failed: {resp}")

    def listdir(self, path="."):
        req_id = self._send(SFTP_OPENDIR, _sftp_str(path.encode()))
        resp = self._wait_response(req_id)
        if resp[0] != "HANDLE":
            raise SSHChannelError(f"opendir failed: {resp}")
        handle = resp[1]
        entries = []
        while True:
            rid = self._send(SFTP_READDIR, _sftp_str(handle))
            r = self._wait_response(rid)
            if r[0] == "STATUS":
                if r[1] == FX_EOF:
                    break
                raise SSHChannelError(f"readdir failed: {r}")
            if r[0] == "NAME":
                for name, lname, attrs in r[1]:
                    if name in (".", ".."):
                        continue
                    entries.append((name, attrs))
                if not r[1]:
                    break
        # close
        rid = self._send(SFTP_CLOSE, _sftp_str(handle))
        self._wait_response(rid)
        return entries

    def close(self):
        try:
            self.ssh.close_channel()
        except Exception:
            pass

    # ─── CLI ──────────────────────────────────────────────
    def run_cli(self, host=None, port=None):
        """Интерактивный SFTP-клиент, как `sftp` в OpenSSH."""
        import shlex
        import os as _os
        os = _os    # для локальных операций (get/put/lls/lcd)
        cwd = self.realpath(".")
        print(f"Connected to {host or self.ssh.host}:{port or self.ssh.port}.")
        while True:
            try:
                line = input("sftp> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                print("Parse error")
                continue
            cmd = parts[0]
            args = parts[1:]

            if cmd in ("exit", "quit", "bye"):
                break
            elif cmd == "pwd":
                print(f"Remote working directory: {cwd}")
            elif cmd == "cd":
                target = args[0] if args else "/"
                if not target.startswith("/"):
                    target = (cwd.rstrip("/") + "/" + target)
                try:
                    p = self.realpath(target)
                    # Проверим, что это каталог
                    attrs = self.stat(p)
                    if not (attrs.get("mode", 0) & 0o040000):
                        print(f"Not a directory: {target}")
                        continue
                    cwd = p
                except Exception as e:
                    print(f"cd: {e}")
            elif cmd == "ls":
                target = args[0] if args else cwd
                if not target.startswith("/"):
                    target = (cwd.rstrip("/") + "/" + target)
                try:
                    entries = self.listdir(target)
                    for name, attrs in sorted(entries):
                        mode = attrs.get("mode", 0)
                        size = attrs.get("size", 0)
                        kind = "d" if (mode & 0o040000) else "-"
                        print(f"{kind} {mode:07o} {size:>10} {name}")
                except Exception as e:
                    print(f"ls: {e}")
            elif cmd == "lls":
                import os
                target = args[0] if args else "."
                for name in sorted(os.listdir(target)):
                    print(name)
            elif cmd == "lpwd":
                import os
                print(f"Local working directory: {os.getcwd()}")
            elif cmd == "lcd":
                import os
                target = args[0] if args else os.path.expanduser("~")
                try:
                    os.chdir(target)
                except Exception as e:
                    print(f"lcd: {e}")
            elif cmd == "mkdir":
                if not args:
                    print("usage: mkdir <path>")
                    continue
                target = args[0]
                if not target.startswith("/"):
                    target = (cwd.rstrip("/") + "/" + target)
                try:
                    self.mkdir(target)
                    print(f"Created directory {target}")
                except Exception as e:
                    print(f"mkdir: {e}")
            elif cmd == "rmdir":
                if not args:
                    print("usage: rmdir <path>")
                    continue
                target = args[0]
                if not target.startswith("/"):
                    target = (cwd.rstrip("/") + "/" + target)
                try:
                    self.rmdir(target)
                    print(f"Removed directory {target}")
                except Exception as e:
                    print(f"rmdir: {e}")
            elif cmd == "rm":
                if not args:
                    print("usage: rm <path>")
                    continue
                target = args[0]
                if not target.startswith("/"):
                    target = (cwd.rstrip("/") + "/" + target)
                try:
                    self.remove(target)
                    print(f"Removed {target}")
                except Exception as e:
                    print(f"rm: {e}")
            elif cmd == "rename":
                if len(args) < 2:
                    print("usage: rename <old> <new>")
                    continue
                old, new = args[0], args[1]
                if not old.startswith("/"):
                    old = (cwd.rstrip("/") + "/" + old)
                if not new.startswith("/"):
                    new = (cwd.rstrip("/") + "/" + new)
                try:
                    self.rename(old, new)
                    print(f"Renamed {old} -> {new}")
                except Exception as e:
                    print(f"rename: {e}")
            elif cmd == "get":
                if not args:
                    print("usage: get <remote> [local]")
                    continue
                remote = args[0]
                local = args[1] if len(args) > 1 else os.path.basename(remote)
                if not remote.startswith("/"):
                    remote = (cwd.rstrip("/") + "/" + remote)
                try:
                    self._get(remote, local)
                    print(f"Fetched {remote} to {local}")
                except Exception as e:
                    print(f"get: {e}")
            elif cmd == "put":
                if not args:
                    print("usage: put <local> [remote]")
                    continue
                local = args[0]
                remote = args[1] if len(args) > 1 else ("/" + os.path.basename(local))
                if not remote.startswith("/"):
                    remote = (cwd.rstrip("/") + "/" + remote)
                try:
                    self._put(local, remote)
                    print(f"Uploaded {local} to {remote}")
                except Exception as e:
                    print(f"put: {e}")
            elif cmd == "help":
                print("Commands: ls, cd, pwd, lls, lpwd, lcd, mkdir, rmdir, rm, rename, get, put, exit")
            else:
                print(f"Invalid command: {cmd}")
        self.close()

    # ─── чтение/запись файлов ─────────────────────────────
    def open(self, path, pflags, mode=0o644):
        """Открыть файл. pflags — SSH_FXF_*."""
        attrs = _sftp_u32(SSH_FILEXFER_ATTR_PERMISSIONS) + _sftp_u32(mode)
        req_id = self._send(SFTP_OPEN, _sftp_str(path.encode())
                            + _sftp_u32(pflags) + attrs)
        resp = self._wait_response(req_id)
        if resp[0] == "HANDLE":
            return resp[1]
        raise SSHChannelError(f"open {path!r} failed: {resp}")

    def read(self, handle, offset, length):
        req_id = self._send(SFTP_READ, _sftp_str(handle)
                            + _sftp_u64(offset) + _sftp_u32(length))
        resp = self._wait_response(req_id)
        if resp[0] == "DATA":
            return resp[1]
        if resp[0] == "STATUS" and resp[1] == FX_EOF:
            return b""
        raise SSHChannelError(f"read failed: {resp}")

    def write(self, handle, offset, data):
        req_id = self._send(SFTP_WRITE, _sftp_str(handle)
                            + _sftp_u64(offset) + _sftp_str(data))
        resp = self._wait_response(req_id)
        if resp[0] == "STATUS" and resp[1] == FX_OK:
            return
        raise SSHChannelError(f"write failed: {resp}")

    def fstat(self, handle):
        req_id = self._send(SFTP_FSTAT, _sftp_str(handle))
        resp = self._wait_response(req_id)
        if resp[0] == "ATTRS":
            attrs, _ = self._parse_attrs(resp[1], 0)
            return attrs
        raise SSHChannelError(f"fstat failed: {resp}")

    def _get(self, remote, local):
        """Скачать файл."""
        handle = self.open(remote, SSH_FXF_READ)
        try:
            attrs = self.fstat(handle)
            size = attrs.get("size", 0)
            received = 0
            with open(local, "wb") as f:
                while True:
                    chunk = self.read(handle, received, 32768)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    if size:
                        pct = 100 * received // size
                        print(f"\r{os.path.basename(local)}  {pct:3d}%  "
                              f"{received}/{size}", end="", flush=True)
            if size:
                print()
        finally:
            self.close_handle(handle)

    def _put(self, local, remote):
        """Загрузить файл."""
        size = os.path.getsize(local)
        handle = self.open(remote,
                           SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
        try:
            sent = 0
            with open(local, "rb") as f:
                while True:
                    chunk = f.read(32768)
                    if not chunk:
                        break
                    self.write(handle, sent, chunk)
                    sent += len(chunk)
                    pct = 100 * sent // size if size else 100
                    print(f"\r{os.path.basename(local)}  {pct:3d}%  "
                          f"{sent}/{size}", end="", flush=True)
            if size:
                print()
        finally:
            self.close_handle(handle)

    def close_handle(self, handle):
        req_id = self._send(SFTP_CLOSE, _sftp_str(handle))
        self._wait_response(req_id)

    # ─── файловые операции ────────────────────────────────
    def mkdir(self, path, mode=0o755):
        attrs = _sftp_u32(SSH_FILEXFER_ATTR_PERMISSIONS) + _sftp_u32(mode)
        req_id = self._send(SFTP_MKDIR, _sftp_str(path.encode()) + attrs)
        resp = self._wait_response(req_id)
        if resp[0] == "STATUS" and resp[1] == FX_OK:
            return
        raise SSHChannelError(f"mkdir {path!r} failed: {resp}")

    def rmdir(self, path):
        req_id = self._send(SFTP_RMDIR, _sftp_str(path.encode()))
        resp = self._wait_response(req_id)
        if resp[0] == "STATUS" and resp[1] == FX_OK:
            return
        raise SSHChannelError(f"rmdir {path!r} failed: {resp}")

    def remove(self, path):
        req_id = self._send(SFTP_REMOVE, _sftp_str(path.encode()))
        resp = self._wait_response(req_id)
        if resp[0] == "STATUS" and resp[1] == FX_OK:
            return
        raise SSHChannelError(f"rm {path!r} failed: {resp}")

    def rename(self, old, new):
        req_id = self._send(SFTP_RENAME,
                            _sftp_str(old.encode()) + _sftp_str(new.encode()))
        resp = self._wait_response(req_id)
        if resp[0] == "STATUS" and resp[1] == FX_OK:
            return
        raise SSHChannelError(f"rename {old!r} -> {new!r} failed: {resp}")

class SSHServer:
    VERSION = "SSH-2.0-MySSH_Server_0.1"

    def __init__(self, host_keys, addr, users=None, passwords=None,
                 verbose=False, allowed_commands=None, shell_mode="auto"):
        """
        shell_mode:
          "auto" — попробовать pty, откатиться на pipe (default)
          "pty"  — только pty; при неудаче — CHANNEL_FAILURE
          "pipe" — только pipe (для Pydroid3 и sandbox'ов)
        """
        if shell_mode not in ("auto", "pty", "pipe"):
            raise ValueError(f"shell_mode must be auto|pty|pipe, got {shell_mode!r}")
        self.host_keys = host_keys
        self.addr = addr
        self.users = users
        self.passwords = passwords
        self.verbose = verbose
        self.allowed = allowed_commands or ALLOWED_COMMANDS
        self.shell_mode = shell_mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.listen(8)
        self._running = True

    def serve_forever(self):
        if self.verbose:
            print(f"[server] listening on {self.addr[0]}:{self.addr[1]}")
        while self._running:
            try: client, caddr = self.sock.accept()
            except OSError: break
            threading.Thread(target=self._handle, args=(client, caddr),
                             daemon=True).start()

    def stop(self):
        self._running = False
        try: self.sock.close()
        except Exception: pass

    def _log(self, msg):
        if self.verbose: print(msg)

    def _handle(self, sock, caddr):
        try:
            self._session(sock, caddr)
        except Exception as e:
            self._log(f"[server] {caddr} closed: {type(e).__name__}: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
        finally:
            try: sock.close()
            except Exception: pass

    def _session(self, sock, caddr):
        sock.settimeout(60)
        t = Transport(sock, self.VERSION, is_client=False)
        my_ver, remote_ver = t.exchange_versions()
        self._log(f"[server] {caddr} client: {remote_ver}")

        # Формируем hostkey_algos по фактическому типу ключа
        hk_type = getattr(self.host_keys.public_key, "KEYTYPE", "ssh-ed25519")
        if hk_type == "ssh-ed25519":
            server_hostkey_algos = ["ssh-ed25519"]
        elif hk_type == "ssh-rsa":
            server_hostkey_algos = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        else:
            server_hostkey_algos = [hk_type]

        my_kexinit = build_kexinit(hostkey_algos=server_hostkey_algos)
        t.send(my_kexinit)
        their_kexinit_raw = t.recv()
        their_kexinit = parse_kexinit(their_kexinit_raw)
        algs = negotiate(their_kexinit, hostkey_algos=server_hostkey_algos)
        if algs["kex"] is None or algs["hostkey"] is None or algs["enc_c2s"] is None:
            raise SSHProtocolError("no common algorithms")
        self._log(f"[server] kex={algs['kex']} hostkey={algs['hostkey']} enc={algs['enc_c2s']}")

        init = t.recv()
        C_INIT, _ = read_string(init, 1)

        kex = algs["kex"]
        K_S = self.host_keys.public_key.public_blob()

        if kex == "mlkem768x25519-sha256":
            # Гибрид ML-KEM-768 + X25519
            if len(C_INIT) != 1216:
                raise SSHProtocolError(f"bad C_INIT len: {len(C_INIT)} (expected 1216)")
            mlkem_ek = C_INIT[:1184]
            x_cli_pub = C_INIT[1184:]
            mlkem_ss, mlkem_ct = MLKEM768.encaps(mlkem_ek)
            eph_priv = secrets.token_bytes(32)
            x_srv_pub = X25519.scalarmult_base(eph_priv)
            x_ss = X25519.scalarmult(eph_priv, x_cli_pub)
            K_raw = _mlkem768x25519_shared(mlkem_ss, x_ss)
            S_REPLY = mlkem_ct + x_srv_pub   # 1120 байт
            K_ser = _ssh_string(K_raw)
        else:
            Q_C = C_INIT
            eph_priv = secrets.token_bytes(32)
            Q_S = X25519.scalarmult_base(eph_priv)
            K_raw = X25519.scalarmult(eph_priv, Q_C)
            S_REPLY = Q_S
            K_ser = ssh_mpint(int.from_bytes(K_raw, "big"))

        # H = SHA256(V_C || V_S || I_C || I_S || K_S || C_INIT || S_REPLY || K)
        h = hashlib.sha256()
        h.update(_ssh_string(remote_ver.encode()))
        h.update(_ssh_string(my_ver.encode()))
        h.update(_ssh_string(their_kexinit_raw))
        h.update(_ssh_string(my_kexinit))
        h.update(_ssh_string(K_S))
        h.update(_ssh_string(C_INIT))
        h.update(_ssh_string(S_REPLY))
        h.update(K_ser)
        H = h.digest()

        hk_type = self.host_keys.public_key.KEYTYPE
        if hk_type == "ssh-ed25519":
            raw_sig = self.host_keys.private_key.sign(H)
            sig_algo = b"ssh-ed25519"
        elif hk_type == "ssh-rsa":
            # RSA host key: rsa-sha2-512 для 2048+, иначе rsa-sha2-256
            kbits = self.host_keys.private_key.bits if hasattr(self.host_keys.private_key, "bits") else 2048
            if kbits >= 2048:
                raw_sig = self.host_keys.private_key.sign(H, hash_algo="sha2-512")
                sig_algo = b"rsa-sha2-512"
            else:
                raw_sig = self.host_keys.private_key.sign(H, hash_algo="sha2-256")
                sig_algo = b"rsa-sha2-256"
        else:
            raise SSHProtocolError(f"unsupported host key: {hk_type}")

        sig_blob = _ssh_string(sig_algo) + _ssh_string(raw_sig)

        t.send(bytes([MSG_KEX_ECDH_REPLY])
               + _ssh_string(K_S) + _ssh_string(S_REPLY) + _ssh_string(sig_blob))
        self._log(f"[server] -> KEX_ECDH_REPLY ({sig_algo.decode()})")

        t.send(bytes([MSG_NEWKEYS]))
        t.recv()

        # Strict KEX: reset seq numbers after NEWKEYS
        t.packetizer.seq_send = 0
        t.packetizer.seq_recv = 0

        enc = algs["enc_c2s"]
        if enc == "chacha20-poly1305@openssh.com":
            key_c2s = derive_key(K_ser, H, H, b"C", 64)
            key_s2c = derive_key(K_ser, H, H, b"D", 64)
            iv_c2s = iv_s2c = None
        else:
            iv_c2s  = derive_key(K_ser, H, H, b"A", 12)
            iv_s2c  = derive_key(K_ser, H, H, b"B", 12)
            key_c2s = derive_key(K_ser, H, H, b"C", 32)
            key_s2c = derive_key(K_ser, H, H, b"D", 32)
        t.packetizer.enable_encryption(enc, key_c2s, key_s2c, iv_c2s, iv_s2c)
        self._log("[server] [encryption ON]")

        sr = t.recv()
        svc, _ = read_string(sr, 1)
        t.send(bytes([MSG_SERVICE_ACCEPT]) + _ssh_string(svc))
        self._log(f"[server] <- SERVICE_REQUEST({svc.decode()})")

        session = _Session(t)

        while True:
            pkt = t.recv()
            if pkt[0] == MSG_USERAUTH_REQUEST:
                if self._handle_userauth(t, pkt, H):
                    self._handle_channels(session)
                    return
            elif pkt[0] == MSG_DISCONNECT:
                self._log("[server] client disconnected")
                return

    def _handle_userauth(self, t, pkt, session_id):
        off = 1
        user, off    = read_string(pkt, off)
        service, off = read_string(pkt, off)
        method, off  = read_string(pkt, off)
        method = method.decode()

        if method == "none":
            # RFC 4252 §5.2: server MUST reject "none" with FAILURE.
            self._log(f"[server] <- USERAUTH none ({user.decode()}) — reject")
            t.send(bytes([MSG_USERAUTH_FAILURE])
                   + _ssh_string(b"publickey,password") + b"\x00")
            return False

        if method == "password":
            return self._handle_userauth_password(t, pkt)

        # publickey: дочитываем has_sig_byte
        if off >= len(pkt):
            self._log(f"[server] malformed USERAUTH_REQUEST (method={method})")
            t.send(bytes([MSG_USERAUTH_FAILURE])
                   + _ssh_string(b"publickey,password") + b"\x00")
            return False
        has_sig_byte = pkt[off]; off += 1
        algo, off    = read_string(pkt, off)
        pubkey, off  = read_string(pkt, off)
        user = user.decode(); service = service.decode(); algo = algo.decode()

        pk_algo_b, o = read_string(pubkey, 0)
        pk_algo = pk_algo_b.decode()

        # Парсим публичный ключ по типу
        if pk_algo == "ssh-ed25519":
            pk_raw, o = read_string(pubkey, o)
            rsa_e_b = rsa_n_b = None
        elif pk_algo == "ssh-rsa":
            rsa_e_b, o = read_string(pubkey, o)
            rsa_n_b, o = read_string(pubkey, o)
            pk_raw = None
        else:
            self._log(f"[server] unsupported pk_algo: {pk_algo}")
            t.send(bytes([MSG_USERAUTH_FAILURE])
                   + _ssh_string(b"publickey,password") + b"\x00")
            return False

        if has_sig_byte == 0:
            self._log(f"[server] <- USERAUTH probe ({user}, {pk_algo})")
            t.send(bytes([MSG_USERAUTH_PK_OK])
                   + _ssh_string(algo.encode()) + _ssh_string(pubkey))
            return False

        sig_blob, off = read_string(pkt, off)
        sig_algo_b, o = read_string(sig_blob, 0)
        sig_algo = sig_algo_b.decode()
        sig_raw, o    = read_string(sig_blob, o)

        req_bytes = (bytes([MSG_USERAUTH_REQUEST])
                     + _ssh_string(user.encode())
                     + _ssh_string(service.encode())
                     + _ssh_string(method.encode())
                     + b"\x01"
                     + _ssh_string(algo.encode())
                     + _ssh_string(pubkey))
        to_verify = _ssh_string(session_id) + req_bytes

        # Диспетчер по типу ключа
        ok_sig = False
        try:
            if pk_algo == "ssh-ed25519":
                ok_sig = Ed25519.verify(pk_raw, to_verify, sig_raw)
            elif pk_algo == "ssh-rsa":
                e_int = int.from_bytes(rsa_e_b, "big")
                n_int = int.from_bytes(rsa_n_b, "big")
                rsa_pub = RSAKey.from_components(n_int, e_int)
                algo_name = sig_algo
                if algo_name == "ssh-rsa":
                    algo_name = "rsa-sha2-256"
                ok_sig = rsa_pub.verify(to_verify, sig_raw, algo_name=algo_name)
        except Exception as e:
            self._log(f"[server] verify exception: {type(e).__name__}: {e}")
            ok_sig = False

        self._log(f"[server] <- USERAUTH signed ({user}, {pk_algo}), verify={ok_sig}")

        if not ok_sig:
            t.send(bytes([MSG_USERAUTH_FAILURE])
                   + _ssh_string(b"publickey,password") + b"\x00")
            return False

        # Проверяем, что пользователь и ключ совпадают
        user_match = self.users is None
        if self.users is not None and user in self.users:
            expected = self.users[user]
            try:
                if pk_algo == "ssh-ed25519":
                    # Сравниваем ПУБЛИЧНЫЙ ключ, не seed!
                    if hasattr(expected, "_ed") and expected._ed is not None:
                        expected_pub = expected._ed.public_raw
                    elif hasattr(expected, "_pub_raw"):
                        expected_pub = expected._pub_raw
                    else:
                        expected_pub = None
                    user_match = (expected_pub is not None
                                  and expected_pub == pk_raw)
                elif pk_algo == "ssh-rsa":
                    e_exp = int.from_bytes(rsa_e_b, "big")
                    n_exp = int.from_bytes(rsa_n_b, "big")
                    user_match = (hasattr(expected, "n")
                                  and expected.n == n_exp
                                  and hasattr(expected, "e")
                                  and expected.e == e_exp)
            except Exception as e:
                self._log(f"[server] user_match exception: {type(e).__name__}: {e}")
                user_match = False
        elif self.users is not None:
            self._log(f"[server] user {user!r} не в списке users")

        if not user_match:
            self._log(f"[server] user_match=False (user={user!r}, pk_algo={pk_algo})")

        if user_match:
            t.send(bytes([MSG_USERAUTH_SUCCESS]))
            self._log(f"[server] -> USERAUTH_SUCCESS ({user}) ✓")
            return True
        else:
            t.send(bytes([MSG_USERAUTH_FAILURE])
                   + _ssh_string(b"publickey,password") + b"\x00")
            return False


    def _handle_userauth_password(self, t, pkt):
        off = 1
        u, off        = read_string(pkt, off)
        service, off  = read_string(pkt, off)
        m, off        = read_string(pkt, off)
        has_change    = pkt[off]; off += 1
        password, off = read_string(pkt, off)
        u = u.decode(); password = password.decode()

        ok = False
        if self.passwords and u in self.passwords:
            ok = secrets.compare_digest(
                self.passwords[u].encode("utf-8"), password.encode("utf-8"))
        if ok:
            t.send(bytes([MSG_USERAUTH_SUCCESS]))
            self._log(f"[server] -> USERAUTH_SUCCESS ({u}) ✓")
            return True
        t.send(bytes([MSG_USERAUTH_FAILURE])
               + _ssh_string(b"publickey,password") + b"\x00")
        return False

    def _handle_channels(self, session):
        t = session.t
        try:
            while True:
                pkt = t.recv()
                t0 = pkt[0]
                if t0 == MSG_DISCONNECT:
                    self._log("[server] client disconnected")
                    return
                if t0 == MSG_CHANNEL_OPEN:
                    self._handle_channel_open(session, pkt)
                elif t0 == MSG_CHANNEL_REQUEST:
                    self._handle_channel_request(session, pkt)
                elif t0 == MSG_CHANNEL_DATA:
                    off = 1 + 4
                    data, off = read_string(pkt, off)
                    if session.shell_kind == "sftp" and getattr(session, "sftp", None):
                        session.sftp.feed(data)
                    elif session.shell_kind == "pty" and session.shell_fd is not None:
                        try: os.write(session.shell_fd, data)
                        except OSError: pass
                    elif session.shell_kind == "pipe" and session.shell_stdin is not None:
                        if not data.endswith(b"\n"):
                            data += b"\n"
                        try:
                            session.shell_stdin.write(data)
                            session.shell_stdin.flush()
                        except (BrokenPipeError, OSError):
                            pass
                elif t0 in (MSG_CHANNEL_EOF, MSG_CHANNEL_WINDOW_ADJUST,
                            MSG_CHANNEL_CLOSE, MSG_IGNORE, MSG_DEBUG):
                    pass
                elif t0 == MSG_SERVICE_REQUEST:
                    svc, _ = read_string(pkt, 1)
                    t.send(bytes([MSG_SERVICE_ACCEPT]) + _ssh_string(svc))
                else:
                    self._log(f"[server] unknown msg {t0}")
        finally:
            session.kill_shell()

    def _handle_channel_open(self, session, pkt):
        t = session.t
        off = 1
        ctype, off  = read_string(pkt, off)
        sender = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
        win    = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
        maxp   = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
        self._log(f"[server] <- CHANNEL_OPEN({ctype.decode()}, sender={sender})")

        if ctype != b"session":
            t.send(bytes([MSG_CHANNEL_OPEN_FAILURE])
                   + struct.pack(">I", sender) + struct.pack(">I", 3)
                   + _ssh_string(b"only 'session'") + _ssh_string(b""))
            return

        session.remote_channel = sender
        t.send(bytes([MSG_CHANNEL_OPEN_CONFIRMATION])
               + struct.pack(">I", sender)
               + struct.pack(">I", sender)
               + struct.pack(">I", 2*1024*1024)
               + struct.pack(">I", 32768))
        self._log(f"[server] -> CHANNEL_OPEN_CONFIRMATION(server={sender})")

    def _handle_channel_request(self, session, pkt):
        t = session.t
        off = 1
        recipient = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
        req_type, off = read_string(pkt, off)
        want_reply = pkt[off]; off += 1

        if req_type == b"exec":
            command, off = read_string(pkt, off)
            self._log(f"[server] <- CHANNEL_REQUEST(exec, {command.decode()!r})")
            self._run_exec(session, command.decode(), want_reply)

        elif req_type == b"pty-req":
            term, off = read_string(pkt, off)
            cols = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
            rows = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
            wpx  = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
            hpx  = struct.unpack(">I", pkt[off:off+4])[0]; off += 4
            modes, off = read_string(pkt, off)
            session.pty_info = {"term": term.decode(), "cols": cols, "rows": rows}
            self._log(f"[server] <- CHANNEL_REQUEST(pty-req, {term.decode()}, {cols}x{rows})")
            if want_reply:
                t.send(bytes([MSG_CHANNEL_SUCCESS]) + struct.pack(">I", recipient))

        elif req_type == b"shell":
            self._log("[server] <- CHANNEL_REQUEST(shell)")
            self._run_shell(session, want_reply)

        elif req_type == b"subsystem":
            subsystem, off = read_string(pkt, off)
            subsystem = subsystem.decode(errors="replace")
            self._log(f"[server] <- CHANNEL_REQUEST(subsystem, {subsystem!r})")
            if subsystem == "sftp":
                self._run_sftp(session, want_reply)
            else:
                if want_reply:
                    t.send(bytes([MSG_CHANNEL_FAILURE]) + struct.pack(">I", recipient))

        elif req_type == b"window-change":
            if want_reply:
                t.send(bytes([MSG_CHANNEL_SUCCESS]) + struct.pack(">I", recipient))

        else:
            self._log(f"[server] <- CHANNEL_REQUEST({req_type.decode()}) unsupported")
            if want_reply:
                t.send(bytes([MSG_CHANNEL_FAILURE]) + struct.pack(">I", recipient))

    def _run_sftp(self, session, want_reply):
        """Запустить SFTP-сессию с root jail в домашней директории."""
        t = session.t
        r = session.remote_channel
        if want_reply:
            t.send(bytes([MSG_CHANNEL_SUCCESS]) + struct.pack(">I", r))
        sftp_root = getattr(self, "sftp_root", None) or os.path.expanduser("~")
        session.shell_kind = "sftp"
        session.sftp = SFTPSession(t, r, sftp_root, log=self._log)
        session.send_channel_data(b"")   # пустой первый пакет не нужен
        self._log(f"[server] SFTP session started (root={sftp_root})")

    def _run_exec(self, session, command, want_reply):
        t = session.t
        r = session.remote_channel
        if want_reply:
            t.send(bytes([MSG_CHANNEL_SUCCESS]) + struct.pack(">I", r))
        try:
            parts = shlex.split(command)
        except ValueError as e:
            self._send_output(session, f"parse error: {e}\n".encode(), 1)
            return
        if not parts or parts[0] not in self.allowed:
            output = (f"command not allowed (whitelist: "
                      f"{' '.join(sorted(self.allowed))})\n").encode()
            exit_code = 127
        else:
            try:
                result = subprocess.run(parts, capture_output=True, timeout=5)
                output = result.stdout + result.stderr
                exit_code = result.returncode
            except Exception as e:
                output = f"exec error: {e}\n".encode(); exit_code = 1
        self._send_output(session, output, exit_code)

    def _send_output(self, session, output, exit_code):
        t = session.t
        r = session.remote_channel
        if output:
            t.send(bytes([MSG_CHANNEL_DATA]) + struct.pack(">I", r) + _ssh_string(output))
        t.send(bytes([MSG_CHANNEL_REQUEST]) + struct.pack(">I", r)
               + _ssh_string(b"exit-status") + b"\x00"
               + struct.pack(">I", exit_code))
        t.send(bytes([MSG_CHANNEL_EOF])   + struct.pack(">I", r))
        t.send(bytes([MSG_CHANNEL_CLOSE]) + struct.pack(">I", r))

    # ---------- shell: pty или pipe ----------
    def _run_shell(self, session, want_reply):
        t = session.t
        r = session.remote_channel
        shell_path = os.environ.get("SHELL") or "/bin/sh"

        user = _get_username()
        banner = (f"MySSH Server ({self.VERSION})\n"
                  f"{os.uname().sysname}, {user}\n").encode()

        want_pty  = self.shell_mode in ("auto", "pty")
        want_pipe = self.shell_mode in ("auto", "pipe")

        # ----- попытка pty -----
        if want_pty:
            master_fd = slave_fd = None
            pty_ok = False
            try:
                import pty as _pty
                master_fd, slave_fd = _pty.openpty()
                pty_ok = True
                self._log(f"[server] pty.openpty OK (master={master_fd})")
            except Exception as e:
                self._log(f"[server] pty.openpty failed: {type(e).__name__}: {e}")
                if master_fd is not None:
                    try: os.close(master_fd)
                    except Exception: pass
                if slave_fd is not None:
                    try: os.close(slave_fd)
                    except Exception: pass
                master_fd = slave_fd = None

            if pty_ok:
                if want_reply:
                    t.send(bytes([MSG_CHANNEL_SUCCESS]) + struct.pack(">I", r))
                session.send_channel_data(banner)
                try:
                    if session.pty_info:
                        import fcntl, termios as _t
                        ws = struct.pack("HHHH", session.pty_info["rows"],
                                         session.pty_info["cols"], 0, 0)
                        fcntl.ioctl(slave_fd, _t.TIOCSWINSZ, ws)
                    proc = subprocess.Popen(
                        [shell_path, "-i"],
                        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                        close_fds=True, preexec_fn=os.setsid,
                    )
                    os.close(slave_fd)
                    session.shell_fd = master_fd
                    session.shell_proc = proc
                    session.shell_kind = "pty"
                    self._log(f"[server] shell (pty) pid={proc.pid}")
                    threading.Thread(target=self._pump_pty,
                                     args=(session,), daemon=True).start()
                    return
                except Exception as e:
                    self._log(f"[server] pty spawn failed: {e}")
                    try: os.close(master_fd)
                    except Exception: pass
                    try: os.close(slave_fd)
                    except Exception: pass
                    if self.shell_mode == "pty":
                        if want_reply:
                            t.send(bytes([MSG_CHANNEL_FAILURE])
                                   + struct.pack(">I", r))
                        return

        if not want_pipe:
            if want_reply:
                t.send(bytes([MSG_CHANNEL_FAILURE]) + struct.pack(">I", r))
            return

        # ----- pipe-режим -----
        if want_reply:
            t.send(bytes([MSG_CHANNEL_SUCCESS]) + struct.pack(">I", r))
        session.send_channel_data(banner)
        try:
            proc = subprocess.Popen(
                [shell_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except Exception as e:
            self._log(f"[server] pipe spawn failed: {e}")
            return
        session.shell_proc = proc
        session.shell_stdin = proc.stdin
        session.shell_kind = "pipe"
        self._log(f"[server] shell (pipe) pid={proc.pid}")
        threading.Thread(target=self._pump_pipe,
                         args=(session,), daemon=True).start()

    def _pump_pty(self, session):
        fd = session.shell_fd
        proc = session.shell_proc
        try:
            while True:
                ready, _, _ = select.select([fd], [], [], 0.5)
                if fd in ready:
                    try: data = os.read(fd, 4096)
                    except OSError: break
                    if not data: break
                    session.send_channel_data(data)
                elif proc.poll() is not None:
                    try:
                        while True:
                            data = os.read(fd, 4096)
                            if not data: break
                            session.send_channel_data(data)
                    except OSError: pass
                    break
        except Exception as e:
            self._log(f"[server] pump_pty: {e}")
        finally:
            session.send_channel_eof_close()
            self._log("[server] shell pump (pty) finished")

    def _pump_pipe(self, session):
        proc = session.shell_proc
        try:
            while True:
                data = proc.stdout.read(4096)
                if not data: break
                session.send_channel_data(data)
        except Exception as e:
            self._log(f"[server] pump_pipe: {e}")
        finally:
            session.send_channel_eof_close()
            self._log("[server] shell pump (pipe) finished")


# ═══════════════════════════════════════════════════════════════════════
# 12. Демо
# ═══════════════════════════════════════════════════════════════════════
def _detect_shell_mode():
    try:
        import pty as _pty
        m, s = _pty.openpty()
        os.close(m); os.close(s)
        return "pty"
    except Exception:
        return "pipe"

# ═══════════════════════════════════════════════════════════════════════
# Демо
# ═══════════════════════════════════════════════════════════════════════
def _detect_shell_mode():
    try:
        import pty as _pty
        m, s = _pty.openpty()
        os.close(m); os.close(s)
        return "pty"
    except Exception:
        return "pipe"


def demo():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  myssh — SSH на чистом Python. pty + pipe shell.         ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    mode = _detect_shell_mode()
    print(f"[i] shell_mode = {mode!r}")
    if mode == "pipe":
        print("    (pty недоступен — Pydroid3/sandbox; pipe-fallback)")
    print()

    host_keys = SSHKeys(comment="host@demo")
    alice = SSHKeys(comment="alice@demo")
    priv, pub = alice
    print(f"host fp: {host_keys.public_key.fingerprint}")
    print(f"user fp: {pub.fingerprint}")
    print()

    server = SSHServer(
        host_keys=host_keys,
        addr=("127.0.0.1", 2222),
        users={"alice": pub},
        passwords={"bob": "hunter2"},
        shell_mode="auto",
        verbose=False,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    print("[server] слушает на 127.0.0.1:2222")
    print()

    kh_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".demo_known_hosts")
    try: os.remove(kh_file)
    except FileNotFoundError: pass

    # --- [1] exec через API ---
    print("[1] exec через API")
    ssh = SSH(pub, priv, ("127.0.0.1", 2222),
              known_hosts=kh_file, strict=False, verbose=False)
    ssh.authenticate("alice")
    for cmd in ["whoami", "uname", "pwd"]:
        ssh.open_session()
        status, out = ssh.exec_command(cmd)
        ssh.close_channel()
        print(f"    $ {cmd}: {out.decode(errors='replace').strip()} [{status}]")
    ssh.disconnect()
    print()

    # --- [2] интерактивный shell ---
    print("[2] интерактивный shell (openshell)")
    ssh = SSH(pub, priv, ("127.0.0.1", 2222),
              known_hosts=kh_file, strict=True, verbose=False)
    ssh.authenticate("alice")
    if sys.stdin.isatty():
        # Явный перевод строки перед shell — Termux-prompt может ещё висеть
        sys.stdout.write("\r\n")
        sys.stdout.flush()
        try:
            ssh.openshell()
        except SSHError as e:
            print(f"    shell error: {type(e).__name__}: {e}")
    else:
        print("    stdin не tty — openshell пропущен.")
    ssh.close()
    print()

    # --- [3] MITM-защита ---
    print("[3] MITM-защита (known_hosts)")
    fake = SSHKeys(comment="attacker")
    b64 = base64.b64encode(fake.public_key.public_blob()).decode().rstrip("=")
    bad_kh = kh_file + ".evil"
    with open(bad_kh, "w") as f:
        f.write(f"[127.0.0.1]:2222 ssh-ed25519 {b64}\n")
    try:
        SSH(pub, priv, ("127.0.0.1", 2222),
            known_hosts=bad_kh, strict=True, verbose=False)
        print("    ERROR: MITM не обнаружен")
    except SSHHostKeyError as e:
        print(f"    ✓ пойман SSHHostKeyError")
        print(f"      {str(e)[:70]}")
    except Exception as e:
        print(f"    [!] {type(e).__name__}: {e}")
    print()

    # --- [4] пароль на приватный ключ ---
    print("[4] Парольная защита ключа (bcrypt_pbkdf + aes256-ctr)")
    keyfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".demo_encrypted_key")
    PW = "hunter2"
    ROUNDS = 8
    print(f"    шифруем ключ (rounds={ROUNDS})...")
    t0 = time.time()
    priv.save(keyfile, password=PW, rounds=ROUNDS)
    dt_enc = time.time() - t0
    with open(keyfile) as f:
        head = f.readline().strip()
    print(f"    сохранён: {head}  ({dt_enc:.2f}с)")

    t0 = time.time()
    loaded = Key.load(keyfile, password=PW)
    dt_dec = time.time() - t0
    ok_pub = loaded._ed.public_raw == pub.bytes()
    print(f"    расшифрован ({dt_dec:.2f}с), pubkey совпадает: {ok_pub}")

    # очистка временных файлов
    for f in (keyfile, bad_kh):
        try: os.remove(f)
        except FileNotFoundError: pass

    server.stop()
    print()
    print("Готово.")


if __name__ == "__main__":
    demo()
