#!/bin/sh
# compile.sh — всё-в-одном: сборка, установка, патч myssh.py, очистка.
#
# Использование:
#   sh compile.sh                   сборка + установка + тесты
#   sh compile.sh --no-test         без тестов
#   sh compile.sh --verbose         подробно
#   sh compile.sh clean             очистка артефактов сборки
#   sh compile.sh clean --rm-src    + удалить native/*.c/.h
#   sh compile.sh clean --dry-run   показать, что удалится
#   sh compile.sh --help

# =====================================================================
# Аргументы
# =====================================================================
CMD=build
VERBOSE=0
NO_TEST=0
DRY=0
RM_SRC=0

for arg in "$@"; do
    case "$arg" in
        build)      CMD=build ;;
        clean)      CMD=clean ;;
        --verbose|-v)  VERBOSE=1 ;;
        --no-test)  NO_TEST=1 ;;
        --dry-run)  DRY=1 ;;
        --rm-src)   RM_SRC=1 ;;
        --help|-h)  CMD=help ;;
        *)          ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

NATIVE_DIR="$SCRIPT_DIR/native"
C_SRC="$NATIVE_DIR/mysshprimitives.c"
H_SRC="$NATIVE_DIR/mysshprimitives.h"
TBL_H="$NATIVE_DIR/blowfish_tables.h"
SO_OUT="$NATIVE_DIR/libmyssh.so"
PY_MAIN="$SCRIPT_DIR/myssh.py"
# BOOTSTRAP убран — восстановление из git

hr()   { printf '%s\n' "════════════════════════════════════════════════════════════"; }
log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
err()  { printf '[x] %s\n' "$*"; }
dbg()  { [ "$VERBOSE" = "1" ] && printf '    %s\n' "$*"; return 0; }

if [ "$CMD" = "help" ]; then
    sed -n '2,15p' "$0"
    exit 0
fi

# =====================================================================
# Найти Python
# =====================================================================
PY=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then err "Python не найден"; exit 1; fi

PY_PURELIB="$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null)"
PY_DYNLOAD="$("$PY" -c 'import _ctypes,pathlib; print(pathlib.Path(_ctypes.__file__).resolve().parent)' 2>/dev/null)"

# =====================================================================
# CLEAN
# =====================================================================
if [ "$CMD" = "clean" ]; then
    hr
    echo "  Очистка артефактов myssh"
    hr
    echo

    # Список .so через Python
    TMPF="$SCRIPT_DIR/.clean_paths.tmp"
    rm -f "$TMPF"
    "$PY" - > "$TMPF" << 'PY_SCAN'
import sys, sysconfig, pathlib, os
NAMES = ["libmyssh.so", "libbcrypt.so", "libsshxc.so"]
hits = set()
def add(p):
    try:
        p = pathlib.Path(p)
        if p.exists() and p.is_file(): hits.add(str(p.resolve()))
    except Exception: pass
def scan(d, rec=False):
    try:
        d = pathlib.Path(d)
        if not d.exists() or not d.is_dir(): return
        if rec:
            for root, dirs, files in os.walk(str(d)):
                for f in files:
                    if f in NAMES: add(os.path.join(root, f))
        else:
            for n in NAMES: add(d / n)
    except Exception: pass
for key in ("purelib", "platlib", "stdlib", "platstdlib"):
    try: scan(sysconfig.get_paths().get(key))
    except Exception: pass
try:
    import _ctypes
    scan(pathlib.Path(_ctypes.__file__).resolve().parent)
except Exception: pass
try:
    exe = pathlib.Path(sys.executable).resolve()
    scan(exe.parent); scan(exe.parent.parent / "lib", rec=True)
except Exception: pass
p = os.environ.get("PREFIX", "")
if p:
    scan(pathlib.Path(p) / "lib", rec=True)
    scan(pathlib.Path(p) / "lib" / "myssh")
home = pathlib.Path.home()
scan(home / ".local" / "lib" / "myssh")
scan(home / ".local" / "lib", rec=True)
for base in ("/data/user/0", "/data/data"):
    pd = pathlib.Path(base) / "ru.iiec.pydroid3"
    if not pd.exists(): continue
    files = pd / "files"
    if not files.exists(): continue
    for sub in files.iterdir():
        try:
            if sub.is_dir() and "linux" in sub.name:
                scan(sub, rec=True)
        except Exception: pass
scan(pathlib.Path.cwd(), rec=True)
for pth in ("/usr/local/lib", "/usr/lib"):
    scan(pathlib.Path(pth), rec=True)
for p in sorted(hits): print(p)
PY_SCAN

    echo "Обнаружены .so:"
    N_SO=0
    if [ -s "$TMPF" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            printf '    %s\n' "$line"
            N_SO=$((N_SO+1))
        done < "$TMPF"
    else
        echo "    (не найдено)"
    fi
    echo

    echo "Сборочные артефакты:"
    ART=0
    for f in "$NATIVE_DIR/libmyssh.so" "$NATIVE_DIR/libbcrypt.so" \
             "$NATIVE_DIR/libsshxc.so" "$NATIVE_DIR/blowfish_tables.h" \
             "$NATIVE_DIR/.build.log"; do
        if [ -e "$f" ]; then printf '    %s\n' "$f"; ART=$((ART+1)); fi
    done
    for f in "$NATIVE_DIR/"*.o; do
        if [ -e "$f" ]; then printf '    %s\n' "$f"; ART=$((ART+1)); fi
    done
    [ "$ART" = "0" ] && echo "    (не найдено)"
    echo

    echo "Бэкапы и кэш:"
    for f in "$SCRIPT_DIR/myssh.py.bak"* "$SCRIPT_DIR/myssh.py.bak_boot"* \
             "$SCRIPT_DIR/myssh.py.bak_bcrypt"*; do
        [ -e "$f" ] && printf '    %s\n' "$f"
    done
    find "$SCRIPT_DIR" -type d -name "__pycache__" 2>/dev/null | while IFS= read -r d; do
        printf '    %s\n' "$d"
    done
    echo

    if [ "$RM_SRC" = "1" ]; then
        echo "Исходники (будут удалены):"
        for f in "$C_SRC" "$H_SRC" "$SCRIPT_DIR/native/bcrypt_pbkdf.c"; do
            [ -e "$f" ] && printf '    %s\n' "$f"
        done
        echo
    else
        warn "Исходники native/*.c/.h сохранены (--rm-src чтобы удалить)"
        echo
    fi

    if [ "$DRY" = "1" ]; then
        warn "DRY-RUN: ничего не удалено"
        rm -f "$TMPF"
        exit 0
    fi

    printf 'Подтверждаешь? [y/N] '
    read -r ans
    case "$ans" in
        y|Y|yes|YES) ;;
        *) echo "Отменено."; rm -f "$TMPF"; exit 0 ;;
    esac
    echo
    hr
    log "Удаление..."
    echo

    if [ -s "$TMPF" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            rm -f "$line" 2>/dev/null && ok "rm $line"
        done < "$TMPF"
    fi
    rm -f "$TMPF"

    for f in "$NATIVE_DIR/libmyssh.so" "$NATIVE_DIR/libbcrypt.so" \
             "$NATIVE_DIR/libsshxc.so" "$NATIVE_DIR/blowfish_tables.h" \
             "$NATIVE_DIR/.build.log"; do
        [ -e "$f" ] && rm -f "$f" && ok "rm $f"
    done
    for f in "$NATIVE_DIR/"*.o; do
        [ -e "$f" ] && rm -f "$f" && ok "rm $f"
    done
    for f in "$SCRIPT_DIR/myssh.py.bak"*; do
        [ -e "$f" ] && rm -f "$f" && ok "rm $f"
    done
    find "$SCRIPT_DIR" -type d -name "__pycache__" 2>/dev/null | while IFS= read -r d; do
        rm -rf "$d" && ok "rm -rf $d"
    done

    if [ "$RM_SRC" = "1" ]; then
        for f in "$C_SRC" "$H_SRC" "$SCRIPT_DIR/native/bcrypt_pbkdf.c"; do
            [ -e "$f" ] && rm -f "$f" && ok "rm $f"
        done
    fi

    echo
    hr
    ok "Очистка завершена"
    hr
    exit 0
fi

# =====================================================================
# BUILD
# =====================================================================
hr
echo "  myssh — сборка и установка"
hr
echo

# --- окружение ---
log "Окружение"
echo "    OS    : $(uname -s) / $(uname -m)"
echo "    проект: $SCRIPT_DIR"
echo "    Python: $PY ($("$PY" --version 2>&1))"
dbg "purelib: $PY_PURELIB"
dbg "dynload: $PY_DYNLOAD"
echo

# --- native/*.c ---
log "Проверка исходников"
if [ ! -f "$C_SRC" ] || [ ! -f "$H_SRC" ]; then
    hr
    echo "  [INFO] native/*.c не найдены — сборка невозможна."
    echo ""
    echo "  [INFO] Is beta not in running"
    hr
    exit 1
fi
ok "исходники на месте"
echo

# --- таблицы Blowfish ---
need_tbl=0
[ ! -f "$TBL_H" ] && need_tbl=1
[ -f "$C_SRC" ] && [ "$C_SRC" -nt "$TBL_H" ] && need_tbl=1

if [ "$need_tbl" = "1" ]; then
    log "Генерация blowfish_tables.h"
    "$PY" - << 'PY_TBL'
import pathlib, time
TBL = pathlib.Path("native/blowfish_tables.h")
t0 = time.time()
def pi_hex(n):
    bits=4*n+64; one=1<<bits
    def at(x):
        t=0; term=one//x; x2=x*x; i=1; s=1
        while term:
            t += s*(term//i); term//=x2; i+=2; s=-s
        return t
    return format((16*at(5)-4*at(239)-3*one) >> (bits-4*n), f"0{n}x")
hexd = pi_hex(8336)
P = [int(hexd[i*8:(i+1)*8],16) for i in range(18)]
S = [[int(hexd[(18+b*256+k)*8:(18+b*256+k+1)*8],16) for k in range(256)] for b in range(4)]
def fmt(v, pl=6, ind="    "):
    return "\n".join(ind+", ".join(f"0x{x:08x}U" for x in v[i:i+pl])+"," for i in range(0,len(v),pl))
out = ["#ifndef MYSSH_BLOWFISH_TABLES_H","#define MYSSH_BLOWFISH_TABLES_H",
       "#include <stdint.h>","","static const uint32_t BF_P[18] = {",
       fmt(P),"};","","static const uint32_t BF_S[4][256] = {"]
for b in range(4): out += ["    {", fmt(S[b],8,"        "), "    },"]
out += ["};","","#endif",""]
TBL.write_text("\n".join(out))
print(f"    OK за {time.time()-t0:.1f} сек")
PY_TBL
    [ -f "$TBL_H" ] || { err "таблица не сгенерировалась"; exit 1; }
    ok "blowfish_tables.h готов"
else
    ok "blowfish_tables.h актуален"
fi
echo

# --- компилятор ---
log "Поиск C-компилятора"
CC=""
for c in clang cc gcc tcc; do
    p="$(command -v "$c" 2>/dev/null)"
    if [ -n "$p" ] && [ -x "$p" ]; then CC="$p"; break; fi
done
if [ -z "$CC" ]; then
    for c in \
        /data/data/com.termux/files/usr/bin/clang \
        /data/data/com.termux/files/usr/bin/cc \
        /data/data/com.termux/files/usr/bin/gcc \
        /data/user/0/ru.iiec.pydroid3/files/aarch64-linux-android/bin/cc \
        /data/user/0/ru.iiec.pydroid3/files/aarch64-linux-android/bin/gcc \
        /usr/bin/cc /usr/bin/gcc
    do
        if [ -x "$c" ]; then CC="$c"; break; fi
    done
fi
if [ -z "$CC" ]; then
    err "Компилятор не найден (Termux: pkg install clang)"
    exit 1
fi
ok "Компилятор: $CC"
echo

# --- сборка ---
log "Сборка libmyssh.so"
# На мобильных sandbox'ах arch-специфичные флаги дают Bus error,
# поэтому используем только -O3 без -march/-maes.
CFLAGS="-O3 -fno-strict-aliasing -shared -fPIC -I$NATIVE_DIR"
dbg "cmd: $CC $CFLAGS -o $SO_OUT $C_SRC"
"$CC" $CFLAGS -o "$SO_OUT" "$NATIVE_DIR"/*.c 2>"$NATIVE_DIR/.build.log"
RC=$?
if [ "$RC" != "0" ] || [ ! -f "$SO_OUT" ]; then
    err "Сборка не удалась"
    if [ -f "$NATIVE_DIR/.build.log" ]; then
        sed 's/^/    /' "$NATIVE_DIR/.build.log" | head -40
    fi
    exit 1
fi
SIZE="$(stat -c%s "$SO_OUT" 2>/dev/null || wc -c < "$SO_OUT")"
ok "libmyssh.so ($SIZE байт)"
echo

# --- установка ---
log "Установка .so"
N_INST=0
if [ -n "$PY_PURELIB" ]; then
    mkdir -p "$PY_PURELIB" 2>/dev/null
    if cp -f "$SO_OUT" "$PY_PURELIB/libmyssh.so" 2>/dev/null; then
        ok "  → $PY_PURELIB/libmyssh.so"
        N_INST=$((N_INST+1))
    else
        warn "  ✗ не смог записать в $PY_PURELIB"
    fi
fi
if [ -n "$PY_DYNLOAD" ]; then
    mkdir -p "$PY_DYNLOAD" 2>/dev/null
    if cp -f "$SO_OUT" "$PY_DYNLOAD/libmyssh.so" 2>/dev/null; then
        ok "  → $PY_DYNLOAD/libmyssh.so"
        N_INST=$((N_INST+1))
    fi
fi
[ "$N_INST" = "0" ] && { err "не удалось установить"; exit 1; }
ok "установлено в $N_INST мест"
echo

# --- патч myssh.py (идемпотентный) ---
log "Патч myssh.py"
"$PY" - << 'PY_PATCH' || true
import pathlib, re, sys, ast

p = pathlib.Path("myssh.py")
if not p.exists():
    print("    [!] myssh.py не найден — пропускаю")
    sys.exit(0)

src = p.read_text()
orig = src
changes = []

# --- 1. Переименовать class Ed25519 → _Ed25519_Py (только если ещё не) ---
if "class Ed25519:" in src:
    src = src.replace("class Ed25519:", "class _Ed25519_Py:", 1)
    changes.append("class Ed25519 → _Ed25519_Py")

# --- 2. Вставить _load_primitives если нет ---
if "_load_primitives" not in src:
    LOADER = '''

# ═══════════════════════════════════════════════════════════════════════
# Загрузчик C-примитивов (libmyssh.so)
# ═══════════════════════════════════════════════════════════════════════
def _load_primitives():
    import ctypes as _ct, pathlib as _pl, sysconfig as _sc, sys as _sys
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
    for _p in cands:
        if not _p.exists(): continue
        try:
            lib = _ct.CDLL(str(_p))
            _U8 = _ct.c_ubyte; _PU8 = _ct.POINTER(_U8); _sz = _ct.c_size_t
            _CP  = _ct.c_char_p
            lib.myssh_x25519_scalarmult_base.argtypes = [_PU8, _PU8]
            lib.myssh_x25519_scalarmult_base.restype = _ct.c_int
            lib.myssh_x25519_scalarmult.argtypes = [_PU8, _PU8, _PU8]
            lib.myssh_x25519_scalarmult.restype = _ct.c_int
            lib.myssh_sha256.argtypes = [_PU8, _sz, _PU8]
            lib.myssh_sha256.restype = None
            lib.myssh_sha512.argtypes = [_PU8, _sz, _PU8]
            lib.myssh_sha512.restype = None
            lib.myssh_aes256_gcm_encrypt.argtypes = [_PU8, _PU8, _PU8, _sz, _PU8, _sz, _PU8]
            lib.myssh_aes256_gcm_encrypt.restype = _ct.c_int
            lib.myssh_aes256_gcm_decrypt.argtypes = [_PU8, _PU8, _PU8, _sz, _PU8, _sz, _PU8]
            lib.myssh_aes256_gcm_decrypt.restype = _ct.c_int
            # bcrypt принимает bytes — используем c_char_p (НЕ PU8!)
            lib.myssh_bcrypt_pbkdf.argtypes = [_CP, _sz, _CP, _sz, _CP, _sz, _ct.c_uint32]
            lib.myssh_bcrypt_pbkdf.restype = _ct.c_int
            try:
                lib.myssh_ed25519_pubkey.argtypes = [_PU8, _PU8]
                lib.myssh_ed25519_pubkey.restype = None
                lib.myssh_ed25519_sign.argtypes = [_PU8, _PU8, _sz, _PU8]
                lib.myssh_ed25519_sign.restype = _ct.c_int
                lib.myssh_ed25519_verify.argtypes = [_PU8, _PU8, _sz, _PU8]
                lib.myssh_ed25519_verify.restype = _ct.c_int
            except AttributeError:
                pass
            return lib, str(_p)
        except OSError:
            continue
    return None, None


_PRIM_C, _PRIM_C_PATH = _load_primitives()
if _PRIM_C is not None:
    print(f"[primitives] C backend: {_PRIM_C_PATH}")


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
'''
    anchor = "_FAKE_USERS"
    idx = src.find(anchor)
    if idx < 0:
        idx = src.find("\nclass SSH:")
    if idx > 0:
        src = src[:idx] + LOADER + "\n\n" + src[idx:]
        changes.append("_load_primitives добавлен")

# --- 3. Fix bcrypt argtypes, если остались старые ---
OLD1 = "lib.myssh_bcrypt_pbkdf.argtypes = [_PU8, _sz, _PU8, _sz, _PU8, _sz, _ct.c_uint32]"
OLD2 = "lib.myssh_bcrypt_pbkdf.argtypes = [_PU8, _sz, _PU8, _sz, _PU8, _sz, ctypes.c_uint32]"
NEW  = "lib.myssh_bcrypt_pbkdf.argtypes = [_ct.c_char_p, _sz, _ct.c_char_p, _sz, _ct.c_char_p, _sz, _ct.c_uint32]"
for old in (OLD1, OLD2):
    if old in src:
        src = src.replace(old, NEW)
        changes.append("bcrypt argtypes → c_char_p")

# --- 4. Диспетчер Ed25519 если ещё нет ---
if "_Ed25519_C" not in src:
    NEW_ED = '''

class _Ed25519_C:
    def __init__(self, seed):
        if len(seed) != 32: raise ValueError("seed must be 32 bytes")
        import ctypes as _ct
        self.seed = bytearray(seed)
        _U8 = _ct.c_ubyte
        sb = (_U8*32).from_buffer_copy(bytes(seed)); pb = (_U8*32)()
        _PRIM_C.myssh_ed25519_pubkey(sb, pb)
        self._pub = bytes(pb); self._wiped = False
    @classmethod
    def generate(cls):
        import secrets as _s; return cls(_s.token_bytes(32))
    @property
    def public_raw(self): return self._pub
    def wipe(self):
        if getattr(self, "_wiped", True): return
        for i in range(len(self.seed)): self.seed[i] = 0
        self._wiped = True
    def __del__(self):
        try: self.wipe()
        except Exception: pass
    def sign(self, msg):
        if self._wiped: raise RuntimeError("key wiped")
        import ctypes as _ct
        _U8 = _ct.c_ubyte
        sb = (_U8*32).from_buffer_copy(bytes(self.seed))
        mb = (_U8*len(msg)).from_buffer_copy(msg) if msg else (_U8*1)()
        sig = (_U8*64)()
        if _PRIM_C.myssh_ed25519_sign(sb, mb, len(msg), sig) != 0:
            raise ValueError("ed25519_sign failed")
        return bytes(sig)
    @classmethod
    def verify(cls, pub_raw, msg, sig):
        if len(pub_raw) != 32 or len(sig) != 64: return False
        import ctypes as _ct
        _U8 = _ct.c_ubyte
        pb = (_U8*32).from_buffer_copy(pub_raw)
        mb = (_U8*len(msg)).from_buffer_copy(msg) if msg else (_U8*1)()
        sg = (_U8*64).from_buffer_copy(sig)
        return _PRIM_C.myssh_ed25519_verify(pb, mb, len(msg), sg) == 1


if _PRIM_C is not None and hasattr(_PRIM_C, "myssh_ed25519_pubkey"):
    Ed25519 = _Ed25519_C
    print("[ed25519] C backend active")
'''
    for anchor in ("\nclass SSHKeys:", "\nclass SSH:"):
        idx = src.find(anchor)
        if idx > 0:
            src = src[:idx] + NEW_ED + src[idx:]
            changes.append("_Ed25519_C dispatcher")
            break

if src == orig:
    print("    [=] ничего не менялось")
else:
    try:
        ast.parse(src)
    except SyntaxError as e:
        print(f"    [!] SYNTAX: {e}")
        sys.exit(0)
    bak = p.with_suffix(".py.bak_compile")
    bak.write_text(orig)
    p.write_text(src)
    for c in changes:
        print(f"    [+] {c}")
    print(f"    бэкап: {bak.name}")
PY_PATCH
echo

# --- тесты ---
if [ "$NO_TEST" = "0" ]; then
    log "Тесты векторов"
    "$PY" - << 'PY_TEST'
import ctypes, pathlib, sysconfig, sys, time
def find():
    cands = []
    try: cands.append(pathlib.Path(sysconfig.get_paths()["purelib"]) / "libmyssh.so")
    except Exception: pass
    try:
        import _ctypes
        cands.append(pathlib.Path(_ctypes.__file__).resolve().parent / "libmyssh.so")
    except Exception: pass
    for p in cands:
        if p.exists():
            try: return ctypes.CDLL(str(p)), str(p)
            except OSError: pass
    return None, None

lib, path = find()
if lib is None:
    print("    [!] не загрузилась"); sys.exit(1)

U8 = ctypes.c_ubyte; PU8 = ctypes.POINTER(U8); sz = ctypes.c_size_t
def cb(b): return (U8*len(b)).from_buffer_copy(b) if b else (U8*1)()
okc = failc = 0
def check(n, cond, ex=""):
    global okc, failc
    if cond: okc += 1; print(f"    [ok] {n} {ex}".rstrip())
    else:    failc += 1; print(f"    [FAIL] {n} {ex}")

# SHA-256/512
lib.myssh_sha256.argtypes = [PU8, sz, PU8]; lib.myssh_sha256.restype = None
o = (U8*32)(); lib.myssh_sha256(cb(b'abc'), 3, o)
check("SHA-256('abc')", bytes(o).hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

lib.myssh_sha512.argtypes = [PU8, sz, PU8]; lib.myssh_sha512.restype = None
o = (U8*64)(); lib.myssh_sha512(cb(b'abc'), 3, o)
check("SHA-512('abc')", bytes(o).hex().startswith("ddaf35a193617aba"))

# X25519
lib.myssh_x25519_scalarmult.argtypes = [PU8, PU8, PU8]; lib.myssh_x25519_scalarmult.restype = ctypes.c_int
k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
o = (U8*32)(); lib.myssh_x25519_scalarmult(cb(k), cb(u), o)
check("X25519 RFC 7748", bytes(o).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

# AES-GCM
lib.myssh_aes256_gcm_encrypt.argtypes = [PU8, PU8, PU8, sz, PU8, sz, PU8]
lib.myssh_aes256_gcm_encrypt.restype = ctypes.c_int
o = (U8*32)()
lib.myssh_aes256_gcm_encrypt(cb(bytes(32)), cb(bytes(12)), None, 0, cb(bytes(16)), 16, o)
check("AES-GCM NIST", bytes(o).hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")

# bcrypt — argtypes c_char_p
lib.myssh_bcrypt_pbkdf.argtypes = [ctypes.c_char_p, sz, ctypes.c_char_p, sz, ctypes.c_void_p, sz, ctypes.c_uint32]
lib.myssh_bcrypt_pbkdf.restype = ctypes.c_int
o = (U8*32)(); t0 = time.time()
lib.myssh_bcrypt_pbkdf(b"password", 8, b"salt", 4, o, 32, 4)
dt = (time.time()-t0)*1000
check("bcrypt_pbkdf", bytes(o).hex() == "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9", f"({dt:.0f} ms)")

# Ed25519
try:
    lib.myssh_ed25519_pubkey.argtypes = [PU8, PU8]; lib.myssh_ed25519_pubkey.restype = None
    lib.myssh_ed25519_sign.argtypes = [PU8, PU8, sz, PU8]; lib.myssh_ed25519_sign.restype = ctypes.c_int
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pb = (U8*32)(); lib.myssh_ed25519_pubkey(cb(seed), pb)
    check("Ed25519 pubkey", bytes(pb).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
except AttributeError:
    print("    [-] Ed25519 отсутствует")

print()
print(f"    Итог: {okc} ok, {failc} fail")
sys.exit(0 if failc == 0 else 1)
PY_TEST
    [ $? -eq 0 ] && ok "все тесты прошли" || warn "не все тесты прошли"
    echo
fi

# --- интеграция ---
log "Проверка интеграции с myssh.py"
"$PY" - << 'PY_INT' || true
import sys, pathlib, io
sys.path.insert(0, str(pathlib.Path.cwd()))
p = pathlib.Path("myssh.py")
_save = sys.stdout; sys.stdout = io.StringIO()
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("m_t", str(p))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
finally:
    sys.stdout = _save
if "_PRIM_C" in dir(mod) and mod._PRIM_C is not None:
    print(f"    [ok] C backend: {mod._PRIM_C_PATH}")
else:
    print("    [!] myssh.py использует Python-бэкенд")
if "_Ed25519_C" in dir(mod) and mod.Ed25519 is mod._Ed25519_C:
    print("    [ok] Ed25519 на C")
else:
    print("    [!] Ed25519 на Python")
PY_INT
echo

hr
ok "Готово"
hr
echo
echo "Демо:         python3 $PY_MAIN"
echo "Пересборка:   sh $0"
echo "Очистка:      sh $0 clean"
echo "Полная чист.: sh $0 clean --rm-src"
echo
