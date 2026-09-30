# myssh — SSH/SFTP на чистом Python + своя криптография на C

Полностью самостоятельная реализация SSH-2.0 + SFTP v3 + post-quantum KEX (mlkem768x25519-sha256). Совместима с OpenSSH 10.x в обе стороны.

Без paramiko, cryptography, pynacl, liboqs. Только Python stdlib + свой C-код.

---

## Возможности

- SSH-2.0 (RFC 4251-4254)
- SFTP v3 (draft-ietf-secsh-filexfer-02) — клиент + сервер
- KEX: curve25519-sha256, mlkem768x25519-sha256 (post-quantum!)
- Host keys: ssh-ed25519, ssh-rsa (rsa-sha2-256/512)
- Ciphers: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com
- Userauth: publickey (Ed25519, RSA), password
- Channels: session, exec, shell, pty-req, subsystem
- known_hosts: plain + hashed + TOFU, MITM-детект
- Интерактивный shell: PTY + pipe-fallback

### Криптография (всё своё, на C)

| Примитив | Файл | Назначение |
|---|---|---|
| SHA-256/512 | mysshprimitives.c | fingerprints, exchange hash, KDF |
| SHA3-256/512 | sha3.c | ML-KEM (FIPS 202) |
| SHAKE128/256 | sha3.c | ML-KEM sampling |
| X25519 | mysshprimitives.c | KEX curve25519-sha256 |
| Ed25519 | mysshprimitives.c | host key, userauth |
| RSA (PKCS#1 v1.5) | rsa.c | host key, userauth |
| AES-256-GCM | mysshprimitives.c | cipher |
| AES-256-CTR | mysshprimitives.c | encrypted private keys |
| ChaCha20-Poly1305 | chacha20poly1305.c | cipher |
| Blowfish | mysshprimitives.c | bcrypt_pbkdf |
| bcrypt_pbkdf | mysshprimitives.c | encrypted private keys |
| ML-KEM-768 | mlkem.c | PQ KEX (FIPS 203) |

### ML-KEM-768 (FIPS 203)

- NLT над Z_3329[X]/(X^256+1) — Montgomery domain
- SampleNTT (rejection sampling hз SHAKE128)
- SamplePolyCBD (eta = 2)
- Compress / Decompress (d = 1, 4, 10)
- ByteEncode / ByteDecode (d = 1, 4, 10, 12)
- K-PKE (KeyGen, Encrypt, Decrypt)
- ML-KEM (KeyGen, Encaps, Decaps — FO-трансформ с implicit rejection)

---

## Установка

Termux (Android):
    pkg install python clang
    git clone https://github.com/your-username/myssh.git
    cd myssh
    sh install.sh

Другие Unix:
    git clone https://github.com/your-username/myssh.git
    cd myssh
    sh install.sh

install.sh делает:
1. Находит Python и C-компилятор.
2. Генерирует blowfish_tables.h (из pi).
3. Собирает libmyssh.so.
4. Устанавливает .so в site-packages.
5. Прогоняет самотесты.
6. Создаёт якорный бэкап.

---

## Использование

### Демо

    python 3 myssh.py

Functional tests:
    python3 test_myssh.py
    python3 stress_audit.py

### SFTP CLI

    python3 mysftp.py user@host -p 22 -i ~/.ssh/id_ed25519

Vnutri: ls, cd, pwd, get, put, mkdir, rmdir, rm, rename, exit

---

## Архитектура

Python (myssh.py, ~3800 строк):
- SSH-протокол (KEXINIT, KEX, USERAUTH)
- SFTP v3 (сервер + клиент)
- ML-KEM обертки (ctypes)

C (native, ~2500 строк):
- Вся криптопримитивы
- ML-KEM-768 (FIPS 203)

---

## Безопасность

��роект — обучающий. Не проходил независимого аудита.
Можно использовать в доверенной сети.
NE для публичного production.

---

## Лицензия

MIT. См. LICENSE.
