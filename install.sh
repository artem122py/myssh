#!/bin/sh
# install.sh — установка myssh: сборка, тесты, бэкап.
#
# Использование:
#   sh install.sh                # сборка + установка + тесты + бэкап
#   sh install.sh --no-test      # без тестов
#   sh install.sh --no-backup    # без бэкапа
#   sh install.sh --quiet        # минимум вывода
#   sh install.sh --help
#
# Что делает:
#   1. Проверяет окружение (Python, C-компилятор).
#   2. Генерирует blowfish_tables.h (если нужно).
#   3. Собирает native/*.c → libmyssh.so.
#   4. Устанавливает .so в site-packages + lib-dynload.
#   5. Запускает самотесты C-примитивов.
#   6. Запускает test_myssh.py.
#   7. Создаёт якорный бэкап всего важного в ./backups/.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

VERBOSE=1
NO_TEST=0
NO_BACKUP=0

for arg in "$@"; do
    case "$arg" in
        --quiet|-q)   VERBOSE=0 ;;
        --no-test)    NO_TEST=1 ;;
        --no-backup)  NO_BACKUP=1 ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0
            ;;
    esac
done

hr() { printf '%s\n' "════════════════════════════════════════════════════════════"; }
log() { [ "$VERBOSE" = "1" ] && printf '[*] %s\n' "$*"; return 0; }
ok()  { printf '[+] %s\n' "$*"; }
err() { printf '[x] %s\n' "$*" >&2; }
warn(){ printf '[!] %s\n' "$*"; }

hr
echo "  myssh — установка"
hr
echo

# ─── 1. Python ────────────────────────────────────────────────
log "Поиск Python"
PY=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        PY="$cand"; break
    fi
done
if [ -z "$PY" ]; then
    err "Python не найден. Установи: pkg install python"
    exit 1
fi
PY_VER="$("$PY" -c 'import sys; print(sys.version.split()[0])')"
PY_PURELIB="$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
PY_DYNLOAD="$("$PY" -c 'import _ctypes,pathlib; print(pathlib.Path(_ctypes.__file__).resolve().parent)')"
ok "Python $PY_VER"
log "  purelib: $PY_PURELIB"
log "  dynload: $PY_DYNLOAD"
echo

# ─── 2. C-компилятор ──────────────────────────────────────────
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
        /usr/bin/cc /usr/bin/gcc
    do
        [ -x "$c" ] && { CC="$c"; break; }
    done
fi
if [ -z "$CC" ]; then
    err "C-компилятор не найден. Установи: pkg install clang"
    exit 1
fi
ok "CC = $CC"
echo

# ─── 3. blowfish_tables.h ─────────────────────────────────────
log "Проверка native/blowfish_tables.h"
if [ ! -f native/blowfish_tables.h ]; then
    log "  генерация (π через arcctg Мачина)..."
    "$PY" - << 'PYTBL'
import pathlib, time
TBL = pathlib.Path("native/blowfish_tables.h")
t0 = time.time()

def pi_hex(n):
    bits = 4*n + 64; one = 1 << bits
    def at(x):
        t = 0; term = one // x; x2 = x*x; i = 1; s = 1
        while term:
            t += s*(term//i); term //= x2; i += 2; s = -s
        return t
    return format((16*at(5) - 4*at(239) - 3*one) >> (bits - 4*n), f"0{n}x")

hexd = pi_hex(8336)
P = [int(hexd[i*8:(i+1)*8], 16) for i in range(18)]
S = [[int(hexd[(18+b*256+k)*8:(18+b*256+k+1)*8], 16) for k in range(256)] for b in range(4)]

def fmt(v, pl=6, ind="    "):
    return "\n".join(ind + ", ".join(f"0x{x:08x}U" for x in v[i:i+pl]) + "," for i in range(0, len(v), pl))

out = ["#ifndef MYSSH_BLOWFISH_TABLES_H","#define MYSSH_BLOWFISH_TABLES_H",
       "#include <stdint.h>","","static const uint32_t BF_P[18] = {", fmt(P), "};",
       "","static const uint32_t BF_S[4][256] = {"]
for b in range(4):
    out += ["    {", fmt(S[b], 8, "        "), "    },"]
out += ["};","","#endif",""]
TBL.write_text("\n".join(out))
print(f"    OK за {time.time()-t0:.1f} сек")
PYTBL
    ok "blowfish_tables.h создан"
else
    ok "blowfish_tables.h уже есть"
fi
echo

# ─── 4. Сборка libmyssh.so ────────────────────────────────────
log "Сборка libmyssh.so из native/*.c"
CFLAGS="-O3 -fno-strict-aliasing -shared -fPIC -I$SCRIPT_DIR/native"
SO_OUT="$SCRIPT_DIR/native/libmyssh.so"

"$CC" $CFLAGS -o "$SO_OUT" "$SCRIPT_DIR"/native/*.c 2>"$SCRIPT_DIR/native/.build.log"
if [ ! -f "$SO_OUT" ]; then
    err "Сборка не удалась. Лог:"
    sed 's/^/    /' "$SCRIPT_DIR/native/.build.log" | head -30
    exit 1
fi
SIZE="$(stat -c%s "$SO_OUT" 2>/dev/null || wc -c < "$SO_OUT")"
ok "libmyssh.so ($SIZE байт)"
echo

# ─── 5. Установка .so ─────────────────────────────────────────
log "Установка .so"
N_INST=0
for dst in "$PY_PURELIB" "$PY_DYNLOAD"; do
    [ -z "$dst" ] && continue
    mkdir -p "$dst" 2>/dev/null || continue
    if cp -f "$SO_OUT" "$dst/libmyssh.so" 2>/dev/null; then
        ok "  → $dst/libmyssh.so"
        N_INST=$((N_INST+1))
    else
        warn "  ✗ не смог записать в $dst"
    fi
done
if [ "$N_INST" = "0" ]; then
    err "не удалось установить libmyssh.so"
    exit 1
fi
echo

# ─── 6. Самотесты C ───────────────────────────────────────────
if [ "$NO_TEST" = "0" ]; then
    log "Самотесты C-примитивов"
    "$PY" - << 'PYTEST'
import ctypes, pathlib, sysconfig, sys, time

def find_lib():
    cands = []
    try:
        cands.append(pathlib.Path(sysconfig.get_paths()["purelib"]) / "libmyssh.so")
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

lib, path = find_lib()
if lib is None:
    print("    [!] не удалось загрузить libmyssh.so"); sys.exit(1)

ok = 0; fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"    [ok]   {name} {extra}".rstrip())
    else:
        fail += 1
        print(f"    [FAIL] {name} {extra}")

U8 = ctypes.c_ubyte; PU8 = ctypes.POINTER(U8); sz = ctypes.c_size_t
def cb(b): return (U8*len(b)).from_buffer_copy(b) if b else (U8*1)()

lib.myssh_sha256.argtypes = [PU8, sz, PU8]; lib.myssh_sha256.restype = None
o = (U8*32)(); lib.myssh_sha256(cb(b'abc'), 3, o)
check("SHA-256('abc')", bytes(o).hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

lib.myssh_sha512.argtypes = [PU8, sz, PU8]; lib.myssh_sha512.restype = None
o = (U8*64)(); lib.myssh_sha512(cb(b'abc'), 3, o)
check("SHA-512('abc')", bytes(o).hex().startswith("ddaf35a193617aba"))

lib.myssh_x25519_scalarmult.argtypes = [PU8, PU8, PU8]; lib.myssh_x25519_scalarmult.restype = ctypes.c_int
k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
o = (U8*32)(); lib.myssh_x25519_scalarmult(cb(k), cb(u), o)
check("X25519 RFC 7748", bytes(o).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

lib.myssh_aes256_gcm_encrypt.argtypes = [PU8, PU8, PU8, sz, PU8, sz, PU8]
lib.myssh_aes256_gcm_encrypt.restype = ctypes.c_int
o = (U8*32)()
lib.myssh_aes256_gcm_encrypt(cb(bytes(32)), cb(bytes(12)), None, 0, cb(bytes(16)), 16, o)
check("AES-GCM NIST", bytes(o).hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")

lib.myssh_bcrypt_pbkdf.argtypes = [ctypes.c_char_p, sz, ctypes.c_char_p, sz, ctypes.c_void_p, sz, ctypes.c_uint32]
lib.myssh_bcrypt_pbkdf.restype = ctypes.c_int
o = (U8*32)()
lib.myssh_bcrypt_pbkdf(b"password", 8, b"salt", 4, o, 32, 4)
check("bcrypt_pbkdf", bytes(o).hex() == "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9")

try:
    lib.myssh_ed25519_pubkey.argtypes = [PU8, PU8]; lib.myssh_ed25519_pubkey.restype = None
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pb = (U8*32)(); lib.myssh_ed25519_pubkey(cb(seed), pb)
    check("Ed25519 pubkey", bytes(pb).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
except AttributeError:
    print("    [-] Ed25519 не найден")

try:
    lib.myssh_sha3_selftest.restype = ctypes.c_int
    rc = lib.myssh_sha3_selftest()
    check("SHA3/SHAKE NIST", rc == 0, f"(rc={rc})")
except AttributeError:
    print("    [-] SHA3 не найден")

try:
    lib.myssh_chacha20_selftest.restype = ctypes.c_int
    rc = lib.myssh_chacha20_selftest()
    check("ChaCha20-Poly1305 RFC 8439", rc == 0, f"(rc={rc})")
except AttributeError:
    print("    [-] ChaCha self-test не найден")

print()
print(f"    Итого: {ok} ok, {fail} fail")
sys.exit(0 if fail == 0 else 1)
PYTEST
    if [ $? -eq 0 ]; then
        ok "все C-тесты прошли"
    else
        warn "не все C-тесты прошли"
    fi
    echo
fi

# ─── 7. test_myssh.py ─────────────────────────────────────────
if [ "$NO_TEST" = "0" ] && [ -f test_myssh.py ]; then
    log "Запуск test_myssh.py"
    "$PY" test_myssh.py
    TEST_RC=$?
    echo
    if [ $TEST_RC -eq 0 ]; then
        ok "все Python-тесты прошли"
    else
        warn "некоторые Python-тесты упали (rc=$TEST_RC)"
    fi
    echo
fi

# ─── 8. Бэкап ─────────────────────────────────────────────────
if [ "$NO_BACKUP" = "0" ]; then
    log "Создание якорного бэкапа"
    STAMP="$(date +%Y%m%d_%H%M%S)"
    BK_DIR="$SCRIPT_DIR/backups/$STAMP"
    mkdir -p "$BK_DIR"

    # Что бэкапим (не бэкапим бэкапы!)
    for f in \
        myssh.py mysftp.py test_myssh.py serve_sftp_test.py \
        compile.sh install.sh \
        native/*.c native/*.h
    do
        [ -f "$f" ] || continue
        cp "$f" "$BK_DIR/" 2>/dev/null || true
    done

    # host key (если есть)
    [ -f "$HOME/.ssh/myssh_host_key" ] && cp "$HOME/.ssh/myssh_host_key" "$BK_DIR/" 2>/dev/null

    # Последний симлинк на актуальный бэкап
    ln -sfn "$STAMP" "$SCRIPT_DIR/backups/latest" 2>/dev/null

    N_FILES=$(ls -1 "$BK_DIR" 2>/dev/null | wc -l)
    SIZE=$(du -sh "$BK_DIR" 2>/dev/null | awk '{print $1}')
    ok "бэкап: $BK_DIR ($N_FILES файлов, $SIZE)"
    ok "симлинк: backups/latest → $STAMP"
    echo
fi

# ─── 9. Итог ──────────────────────────────────────────────────
hr
ok "Установка завершена"
hr
echo
echo "Запуск демо:      python3 myssh.py"
echo "SFTP CLI:         python3 mysftp.py USER@HOST -p PORT -i KEY"
echo "Свой SFTP-сервер: python3 serve_sftp_test.py"
echo "Тесты:            python3 test_myssh.py"
echo "Переустановка:    sh install.sh"
echo "Бэкапы:           ls backups/"
echo "Восстановление:   cp backups/latest/* . && sh install.sh"
echo
