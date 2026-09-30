#!/usr/bin/env python3
"""Генератор EVM vanity-адресов на BIP-39 seed-фразе (путь m/44'/60'/0'/0/0).

Пример:
    python vanity_seed.py --prefix ab --suffix cd --words 24

Каждая попытка — новый мнемоник (os.urandom через пакет mnemonic), адрес
выводится на индексе 0 стандартного пути: найденная фраза импортируется
в MetaMask/geth/Ledger/Trezor как есть, без дополнительных настроек.

Seed-фраза печатается на экран ОДИН раз — перепиши её на бумагу.
Опционально --save-keystore дополнительно сохраняет выведенный из фразы
ключ в зашифрованный V3 keystore (цифровой бэкап).
"""

import argparse
import getpass
import hashlib
import hmac
import multiprocessing
import os
import sys
import time

from eth_account import Account
from eth_utils import keccak
from mnemonic import Mnemonic

Account.enable_unaudited_hdwallet_features()  # HD-API eth-account, требуется явно

MNEMONIC = Mnemonic("english")
WORDS_TO_STRENGTH = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
MIN_PASSWORD_LEN = 8
PROGRESS_EVERY_SECONDS = 5.0
HEX_CHARS = set("0123456789abcdef")
_SEARCH_BATCH = 32  # фраз на одну задачу воркера (PBKDF2 тяжёлая)
DEFAULT_WORKERS = max(1, (os.cpu_count() or 2) // 2)  # физические ядра
DEFAULT_MAX_INDEX = 10000  # предел индексов на одну фразу в режиме --scan-indexes
# порядок кривой secp256k1 (ключи живут в [1, n-1])
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_BIP32_MASTER_HMAC_KEY = b"Bitcoin seed"
_HARDENED = 0x80000000

BANNER = """
==========================================================
 ВНИМАНИЕ: запускай этот скрипт только на чистой/офлайн-машине.
 Seed-фраза появится на экране один раз — подготовь бумагу и ручку.
==========================================================
"""


def normalize_pattern(pattern: str) -> str:
    """Убирает 0x, приводит к нижнему регистру, проверяет hex-символы."""
    cleaned = pattern.lower().removeprefix("0x")
    if any(c not in HEX_CHARS for c in cleaned):
        raise ValueError(f"шаблон {pattern!r}: только hex-символы (0-9, a-f)")
    return cleaned


def matches(address: str, prefix: str, suffix: str) -> bool:
    """Регистронезависная проверка адреса на префикс/суффикс (без 0x)."""
    addr = address.lower().removeprefix("0x")
    p = prefix.lower().removeprefix("0x")
    s = suffix.lower().removeprefix("0x")
    return addr.startswith(p) and addr.endswith(s)


def generate_mnemonic(words: int = 24) -> str:
    """Новый BIP-39 мнемоник (английский wordlist, энтропия os.urandom)."""
    strength = WORDS_TO_STRENGTH.get(words)
    if strength is None:
        raise ValueError("поддерживаются 12/15/18/21/24 слова")
    return MNEMONIC.generate(strength=strength)


def address_from_mnemonic(phrase: str, passphrase: str = "") -> str:
    """Адрес EVM на стандартном пути m/44'/60'/0'/0/0 (деривация детерминированная)."""
    return Account.from_mnemonic(phrase, passphrase=passphrase).address


# ---------- режим --scan-indexes: одна фраза, много индексов ----------
# PBKDF2 платится один раз на фразу, каждый следующий индекс — дешёвый шаг
# BIP-32 CKD (HMAC-SHA512 + одно умножение на кривой) вместо полной деривации.


def _coincurve():
    """Ленивый импорт, чтобы режим без coincurve продолжал работать."""
    try:
        from coincurve import PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "режим --scan-indexes требует пакет coincurve: uv pip install coincurve"
        ) from exc
    return PublicKey


def _ckd_priv(k: int, cc: bytes, index: int):
    """Один шаг BIP-32 CKD_priv: (k, cc, i) -> (k_child, cc_child)."""
    PublicKey = _coincurve()
    if index >= _HARDENED:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        parent_pub = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        data = parent_pub.format(compressed=True) + index.to_bytes(4, "big")
    digest = hmac.new(cc, data, hashlib.sha512).digest()
    k_child = (int.from_bytes(digest[:32], "big") + k) % SECP256K1_N
    return k_child, digest[32:]


def _bip32_node(phrase: str, passphrase: str = ""):
    """Узел m/44'/60'/0'/0 как (k:int, cc:bytes); PBKDF2 выполняется один раз.

    Используется только как ускоритель деривации: результаты сверяются
    с официальной реализацией eth-account (см. тесты и самопроверку).
    """
    PublicKey = _coincurve()
    from eth_account.hdaccount import seed_from_mnemonic

    seed = seed_from_mnemonic(phrase, passphrase)
    digest = hmac.new(_BIP32_MASTER_HMAC_KEY, seed, hashlib.sha512).digest()
    k, cc = int.from_bytes(digest[:32], "big") % SECP256K1_N, digest[32:]
    for index in (44 + _HARDENED, 60 + _HARDENED, _HARDENED, 0):
        k, cc = _ckd_priv(k, cc, index)
    return k, cc


def address_at_index(node, i: int):
    """Адрес (и ключ) на пути m/44'/60'/0'/0/i из заранее выведенного узла."""
    PublicKey = _coincurve()
    k_child, _cc = _ckd_priv(node[0], node[1], i)
    pub = PublicKey.from_valid_secret(k_child.to_bytes(32, "big"))
    return "0x" + keccak(pub.format(compressed=False)[1:])[-20:].hex(), k_child


def _scan_batch(prefix: str, suffix: str, words: int, passphrase: str, max_index: int):
    """Воркер пула: одна случайная фраза, сканирование до max_index индексов."""
    phrase = generate_mnemonic(words)
    node = _bip32_node(phrase, passphrase)
    for i in range(max_index):
        addr, _k = address_at_index(node, i)
        if matches(addr, prefix, suffix):
            return i + 1, [(phrase, i, addr)]
    return max_index, []


def find_vanity_seed_scan(
    prefix: str = "",
    suffix: str = "",
    words: int = 24,
    passphrase: str = "",
    max_index: int = DEFAULT_MAX_INDEX,
    workers: int = 1,
    progress: bool = True,
):
    """Поиск по индексам: каждая фраза даёт до max_index адресов (m/44'/60'/0'/0/i).

    Возвращает (фраза, индекс, адрес). Найденная пара проверяется ПОЛНОЙ
    официальной деривацией eth-account по всему пути — расхождение невозможно
    тихо пропустить. ВАЖНО: индекс != 0 требует кошелька с кастомным путём
    (Rabby/MEW) или ручного добавления аккаунтов в MetaMask.
    """
    if workers < 1:
        raise ValueError("workers должен быть >= 1")
    if max_index < 1:
        raise ValueError("max_index должен быть >= 1")
    p = normalize_pattern(prefix)
    s = normalize_pattern(suffix)

    class _Prog:
        def __init__(self):
            self.attempts = 0
            self.start = time.monotonic()
            self.next_report = self.start + PROGRESS_EVERY_SECONDS

        def bump(self, n=1):
            self.attempts += n

        def maybe(self):
            now = time.monotonic()
            if not progress or now < self.next_report:
                return
            rate = self.attempts / max(now - self.start, 1e-9)
            print(f"[…] попыток: {self.attempts} ({rate:.0f}/сек)", file=sys.stderr)
            self.next_report = now + PROGRESS_EVERY_SECONDS

        def final(self):
            if progress:
                rate = self.attempts / max(time.monotonic() - self.start, 1e-9)
                print(
                    f"[+] Найдено за {self.attempts} попыток ({rate:.0f}/сек)",
                    file=sys.stderr,
                )

    prog = _Prog()

    def _verify(phrase: str, index: int, addr: str):
        full = Account.from_mnemonic(
            phrase, passphrase=passphrase, account_path=f"m/44'/60'/0'/0/{index}"
        ).address
        if full.lower() != addr.lower() or not matches(full, p, s):
            raise RuntimeError("самопроверка scan-режима не сошлась (CKD != официальный путь)")
        return phrase, index, addr

    if workers == 1:
        while True:
            phrase = generate_mnemonic(words)
            node = _bip32_node(phrase, passphrase)
            for i in range(max_index):
                addr, _k = address_at_index(node, i)
                prog.bump()
                if matches(addr, p, s):
                    result = _verify(phrase, i, addr)
                    prog.final()
                    return result
                prog.maybe()

    with multiprocessing.Pool(workers) as pool:
        while True:
            pending = [
                pool.apply_async(_scan_batch, (p, s, words, passphrase, max_index))
                for _ in range(workers * 4)
            ]
            for result in pending:
                n, found = result.get()
                prog.bump(n)
                prog.maybe()
                if found:
                    phrase, index, addr = found[0]
                    out = _verify(phrase, index, addr)
                    prog.final()
                    return out


def _search_batch(
    prefix: str,
    suffix: str,
    words: int,
    passphrase: str,
    batch: int,
):
    """Воркер пула: batch фраз, возвращает (число попыток, [(фраза, адрес)])."""
    found = []
    for _ in range(batch):
        phrase = generate_mnemonic(words)
        address = address_from_mnemonic(phrase, passphrase)
        if matches(address, prefix, suffix):
            found.append((phrase, address))
    return batch, found


def find_vanity_seed(
    prefix: str = "",
    suffix: str = "",
    words: int = 24,
    passphrase: str = "",
    workers: int = 1,
    progress: bool = True,
):
    """Перебирает свежие мнемоники, пока адрес не совпадёт с шаблоном.

    Возвращает (фраза, адрес); перед возвратом адрес сверяется повторной
    деривацией (защита от ошибки в wordlist/логике).
    workers > 1 — пул процессов (PBKDF2 хорошо параллелится процессами).
    """
    if workers < 1:
        raise ValueError("workers должен быть >= 1")
    p = normalize_pattern(prefix)
    s = normalize_pattern(suffix)
    total = len(p) + len(s)
    if total > 6:
        print(
            f"[i] Шаблон {total} hex-символов: в среднем ~16**{total} попыток,"
            " каждая попытка — это PBKDF2, будет очень долго",
            file=sys.stderr,
        )
    attempts = 0
    start = time.monotonic()
    next_report = start + PROGRESS_EVERY_SECONDS

    def _report(final: bool) -> None:
        if not progress:
            return
        rate = attempts / max(time.monotonic() - start, 1e-9)
        if final:
            print(f"[+] Найдено за {attempts} попыток ({rate:.1f}/сек)", file=sys.stderr)
        else:
            print(f"[…] попыток: {attempts} ({rate:.1f}/сек)", file=sys.stderr)

    def _finish(phrase: str, address: str):
        # самопроверка: повторная деривация обязана дать тот же адрес
        if address_from_mnemonic(phrase, passphrase) != address:
            raise RuntimeError("самопроверка деривации не сошлась")
        _report(final=True)
        return phrase, address

    if workers == 1:
        while True:
            phrase = generate_mnemonic(words)
            address = address_from_mnemonic(phrase, passphrase)
            attempts += 1
            if matches(address, p, s):
                return _finish(phrase, address)
            now = time.monotonic()
            if now >= next_report:
                _report(final=False)
                next_report = now + PROGRESS_EVERY_SECONDS

    with multiprocessing.Pool(workers) as pool:
        while True:
            pending = [
                pool.apply_async(
                    _search_batch, (p, s, words, passphrase, _SEARCH_BATCH)
                )
                for _ in range(workers * 4)
            ]
            for result in pending:
                n, found = result.get()
                attempts += n
                if found:
                    phrase, address = found[0]
                    return _finish(phrase, address)
                now = time.monotonic()
                if now >= next_report:
                    _report(final=False)
                    next_report = now + PROGRESS_EVERY_SECONDS


def prompt_bip39_passphrase() -> str:
    """Опциональная BIP-39 passphrase («25-е слово»); пустая = не использовать."""
    while True:
        pw1 = getpass.getpass(
            "BIP-39 passphrase (Enter = не использовать; деньги без неё НЕ восстановить): "
        )
        pw2 = getpass.getpass("Повторите passphrase: ")
        if pw1 == pw2:
            return pw1
        print("Не совпадают, попробуй ещё раз", file=sys.stderr)


def prompt_keystore_password() -> str:
    while True:
        pw1 = getpass.getpass("Пароль для keystore-файла: ")
        if len(pw1) < MIN_PASSWORD_LEN:
            print(f"Минимум {MIN_PASSWORD_LEN} символов, попробуй ещё раз", file=sys.stderr)
            continue
        pw2 = getpass.getpass("Повторите пароль: ")
        if pw1 == pw2:
            return pw1
        print("Пароли не совпадают, попробуй ещё раз", file=sys.stderr)


def _hex_arg(value: str) -> str:
    try:
        return normalize_pattern(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Генератор EVM vanity-кошельков на BIP-39 seed-фразе",
    )
    parser.add_argument("--prefix", type=_hex_arg, default="", help="начало адреса без 0x")
    parser.add_argument("--suffix", type=_hex_arg, default="", help="конец адреса")
    parser.add_argument("--count", type=int, default=1, help="сколько кошельков найти")
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"число процессов поиска (по умолчанию {DEFAULT_WORKERS} — физические ядра)",
    )
    parser.add_argument(
        "--words", type=int, default=24, choices=sorted(WORDS_TO_STRENGTH), help="длина фразы"
    )
    parser.add_argument(
        "--bip39-passphrase",
        action="store_true",
        help="спросить BIP-39 passphrase (25-е слово; поддерживается не всеми кошельками)",
    )
    parser.add_argument(
        "--scan-indexes",
        action="store_true",
        help="искать по индексам m/44'/60'/0'/0/i (PBKDF2 один раз на фразу,"
        " в десятки раз быстрее; найденный индекс требует кастомного пути)",
    )
    parser.add_argument(
        "--max-index",
        type=int,
        default=DEFAULT_MAX_INDEX,
        help=f"лимит индексов на фразу в --scan-indexes (по умолчанию {DEFAULT_MAX_INDEX})",
    )
    parser.add_argument(
        "--save-keystore",
        action="store_true",
        help="дополнительно сохранить ключ из фразы в зашифрованный V3 keystore",
    )
    parser.add_argument("--keystore-dir", default="keystore", help="куда сохранять keystore")
    args = parser.parse_args(argv)
    if not (args.prefix or args.suffix):
        parser.error("укажи хотя бы один из --prefix / --suffix")
    if args.count < 1:
        parser.error("--count должен быть >= 1")
    if args.workers < 1:
        parser.error("--workers должен быть >= 1")
    if args.max_index < 1:
        parser.error("--max-index должен быть >= 1")

    print(BANNER, file=sys.stderr)
    passphrase = prompt_bip39_passphrase() if args.bip39_passphrase else ""
    keystore_password = None
    if args.save_keystore:
        keystore_password = prompt_keystore_password()

    for i in range(args.count):
        if args.scan_indexes:
            phrase, index, address = find_vanity_seed_scan(
                args.prefix,
                args.suffix,
                args.words,
                passphrase,
                max_index=args.max_index,
                workers=args.workers,
            )
            print(f"[{i + 1}/{args.count}] Адрес: {address}")
            print(f"  Путь деривации: m/44'/60'/0'/0/{index}")
            if index != 0:
                print(
                    "  ВНИМАНИЕ: индекс не 0 — MetaMask покажет этот адрес только"
                    " после ручного добавления аккаунтов; используй кошелёк с"
                    " кастомным путём (Rabby/MEW).",
                    file=sys.stderr,
                )
        else:
            phrase, address = find_vanity_seed(
                args.prefix, args.suffix, args.words, passphrase, workers=args.workers
            )
            print(f"[{i + 1}/{args.count}] Адрес: {address}")
        print("  Перепиши фразу на бумагу (на экране она больше не появится):")
        print(f"  >>> {phrase} <<<")
        print("  Проверь количество слов и только потом закрывай вывод.", file=sys.stderr)
        if args.save_keystore:
            # функции keystore берем из vanity_key, чтобы не дублировать логику
            from vanity_key import build_keystore, save_keystore, verify_keystore

            acct = Account.from_mnemonic(phrase, passphrase=passphrase)
            keystore = build_keystore(acct, keystore_password)
            verify_keystore(keystore, keystore_password, acct.address)
            path = save_keystore(keystore, args.keystore_dir)
            print(f"  Keystore: {path} (права 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
