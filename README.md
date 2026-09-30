# myssh — SSH/SFTP на чистом Python + своя криптография на C

Полностью самостоятельная реализация SSH-2.0 + SFTP v3 + post-quantum KEX
(mlkem768x25519-sha256). Совместима с OpenSSH 10.x в обе стороны.

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
- known_hosts: plain + hashed + TOFU + MITM-детект
- Интерактивный shell: PTY + pipe-fallback

### Криптография (всё своё, на C)

- SHA-256/512 — fingerprints, exchange hash, KDF
- SHA3-256/512 — ML-KEM (FIPS 202)
- SHAKE128/256 — ML-KEM sampling
- X25519 — KEX curve25519-sha256
- Ed25519 — host key, userauth
- RSA (PKCS#1 v1.5) — host key, userauth
- AES-256-GCM — cipher
- AES-256-CTR — encrypted private keys
- ChaCha20-Poly1305 — cipher
- Blowfish — bcrypt_pbkdf
- bcrypt_pbkdf — encrypted private keys
- ML-KEM-768 — PQ KEX (FIPS 203)

---

## Установка

Termux (Android):

    pkg install python clang
    git clone https://github.com/artem122py/myssh.git
    cd myssh
    sh install.sh

Другие Unix:

    git clone https://github.com/artem122py/myssh.git
    cd myssh
    sh install.sh

---

## Использование

Демо:

    python3 myssh.py

SFTP CLI:

    python3 mysftp.py user@host -p 22 -i ~/.ssh/id_ed25519

Внутри: ls, cd, pwd, get, put, mkdir, rmdir, rm, rename, exit

---

## Тесты

    python3 test_myssh.py
    python3 stress_audit.py

---

## Интероп с OpenSSH

Проверено с OpenSSH 10.5:
- Наш клиент в OpenSSH sshd (KEX, host key, userauth, exec, shell, SFTP)
- OpenSSH ssh в наш сервер
- Наш клиент в OpenSSH sshd с PQ-KEX mlkem768x25519-sha256

---

## Безопасность

Проект — обучающий. Не проходил независимый аудит.
Не стоит использовать для production SSH-сервера.

---

## Лицензия

MIT. См. LICENSE.

---

## Ссылки

- RFC 4251-4254 — SSH
- draft-ietf-secsh-filexfer-02 — SFTP v3
- FIPS 203 — ML-KEM
- FIPS 202 — SHA-3/SHAKE
- RFC 8032 — Ed25519
- RFC 7748 — X25519
