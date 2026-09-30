#!/bin/sh
# backup.sh — быстрое создание якорного бэкапа без сборки/тестов.
cd "$(dirname "$0")" || exit 1

STAMP="$(date +%Y%m%d_%H%M%S)"
BK_DIR="backups/$STAMP"
mkdir -p "$BK_DIR"

for f in \
    myssh.py mysftp.py test_myssh.py serve_sftp_test.py \
    compile.sh install.sh \
    native/*.c native/*.h
do
    [ -f "$f" ] || continue
    cp "$f" "$BK_DIR/" 2>/dev/null || true
done

[ -f "$HOME/.ssh/myssh_host_key" ] && cp "$HOME/.ssh/myssh_host_key" "$BK_DIR/" 2>/dev/null

ln -sfn "$STAMP" "backups/latest"

N=$(ls -1 "$BK_DIR" 2>/dev/null | wc -l)
SZ=$(du -sh "$BK_DIR" 2>/dev/null | awk '{print $1}')
echo "[+] бэкап: $BK_DIR ($N файлов, $SZ)"
echo "[+] latest → $STAMP"
