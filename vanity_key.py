#!/usr/bin/env python3
"""Генератор EVM vanity-адресов с сохранением ключа в зашифрованный V3 keystore.

Пример:
    python vanity_key.py --prefix ab --suffix cd --count 2

Приватный ключ не печатается и не пишется в plaintext: он сразу шифруется
в стандартный Web3 Secret Storage V3 keystore (scrypt), файл с правами 0600.
Сырой ключ можно увидеть только с явным флагом --show-privkey.

Запускать на чистой/офлайн-машине: ключ какое-то время находится в памяти
процесса, а безопасность файла зависит от ОС.
"""

import argparse
import getpass
import json
import multiprocessing
import os
import sys
import time
from datetime import datetime, timezone

from eth_account import Account
from eth_utils import keccak

MIN_PASSWORD_LEN = 8
PROGRESS_EVERY_SECONDS = 5.0
HEX_CHARS = set("0123456789abcdef")
_SEARCH_BATCH = 256  # ключей на одну задачу воркера
_WALK_BATCH = 512  # шагов блуждания на одну задачу воркера
DEFAULT_WORKERS = max(1, (os.cpu_count() or 2) // 2)  # физические ядра
# порядок кривой secp256k1 (ключи живут в [1, n-1])
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class _Progress:
    """Счётчик попыток с периодическими отчётами в stderr."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.attempts = 0
        self.start = time.monotonic()
        self.next_report = self.start + PROGRESS_EVERY_SECONDS

    def bump(self, n: int = 1) -> None:
        self.attempts += n

    def maybe_report(self) -> None:
        now = time.monotonic()
        if not self.enabled or now < self.next_report:
            return
        rate = self.attempts / max(now - self.start, 1e-9)
        print(f"[…] попыток: {self.attempts} ({rate:.0f}/сек)", file=sys.stderr)
        self.next_report = now + PROGRESS_EVERY_SECONDS

    def final(self) -> None:
        if not self.enabled:
            return
        rate = self.attempts / max(time.monotonic() - self.start, 1e-9)
        print(f"[+] Найдено за {self.attempts} попыток ({rate:.0f}/сек)", file=sys.stderr)

BANNER = """
==========================================================
 ВНИМАНИЕ: запускай этот скрипт только на чистой/офлайн-машине.
 Ключ шифруется в keystore паролем, но пока живёт в RAM процесса.
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


def _search_batch(prefix: str, suffix: str, batch: int):
    """Воркер пула: batch попыток, возвращает (число попыток, [hex-ключей])."""
    found = []
    for _ in range(batch):
        acct = Account.create()
        if matches(acct.address, prefix, suffix):
            found.append(acct.key.hex())
    return batch, found


# ---------- режим --walk: дешёвые шаги +1 от случайного 256-битного старта ----------


def _random_start() -> int:
    """Старт блуждания: uniform в [1, n-1] из os.urandom (rejection sampling).

    БЕЗОПАСНОСТЬ: старт обязан быть случайным 256-битным. «Красивый»/малый старт
    (1, 12345, дата) компрометирует все найденные ключи — их сканируют боты.
    """
    while True:
        k = int.from_bytes(os.urandom(32), "big")
        if 1 <= k < SECP256K1_N:
            return k


def _walk_tools():
    """(класс PublicKey, точка G) — лениво, чтобы режим без coincurve работал."""
    try:
        from coincurve import PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "режим --walk требует пакет coincurve: uv pip install coincurve"
        ) from exc
    return PublicKey, PublicKey.from_valid_secret((1).to_bytes(32, "big"))


def _address_of(pubkey) -> str:
    """Адрес Ethereum из публичной точки (последние 20 байт keccak256 pubkey)."""
    return "0x" + keccak(pubkey.format(compressed=False)[1:])[-20:].hex()


def walk_addresses(start: int, count: int):
    """Генератор (адрес, ключ) для start, start+1, ... — count шагов блуждания.

    Каждый шаг — одно сложение точек P += G (~мкс) вместо полного k·G.
    """
    PublicKey, G = _walk_tools()
    k = start
    pub = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
    for _ in range(count):
        yield _address_of(pub), k
        pub = pub.combine([G])
        k += 1


def _walk_batch(prefix: str, suffix: str, batch: int):
    """Воркер пула: блуждание от СВОЕГО случайного старта, batch шагов."""
    found = None
    done = 0
    for addr, k in walk_addresses(_random_start(), batch):
        done += 1
        if matches(addr, prefix, suffix):
            found = (k.to_bytes(32, "big").hex(), addr)
            break
    return done, ([found] if found else [])


def find_vanity_walk(
    prefix: str = "",
    suffix: str = "",
    workers: int = 1,
    progress: bool = True,
):
    """Поиск блужданием: случайный старт k0, далее дешёвые шаги k+1 (P += G).

    Энтропийно эквивалентен независимым случайным ключам (старт uniform из
    os.urandom, у каждого воркера свой). Найденный ключ проходит ПОЛНУЮ
    независимую проверку: честное k·G заново + сверка адреса и шаблона.
    """
    if workers < 1:
        raise ValueError("workers должен быть >= 1")
    p = normalize_pattern(prefix)
    s = normalize_pattern(suffix)
    total = len(p) + len(s)
    if total > 6:
        print(
            f"[i] Шаблон {total} hex-символов: в среднем ~16**{total} попыток",
            file=sys.stderr,
        )
    prog = _Progress(progress)

    def _verify(key_hex: str, seen_addr: str):
        acct = Account.from_key(bytes.fromhex(key_hex))
        if acct.address.lower() != seen_addr.lower() or not matches(acct.address, p, s):
            raise RuntimeError("самопроверка блуждания не сошлась (k·G != инкрементам)")
        return acct

    if workers == 1:
        while True:
            for addr, k in walk_addresses(_random_start(), _WALK_BATCH):
                prog.bump()
                if matches(addr, p, s):
                    acct = _verify(k.to_bytes(32, "big").hex(), addr)
                    prog.final()
                    return acct
                prog.maybe_report()

    with multiprocessing.Pool(workers) as pool:
        while True:
            pending = [
                pool.apply_async(_walk_batch, (p, s, _WALK_BATCH))
                for _ in range(workers * 4)
            ]
            for result in pending:
                n, found = result.get()
                prog.bump(n)
                prog.maybe_report()
                if found:
                    key_hex, addr = found[0]
                    acct = _verify(key_hex, addr)
                    prog.final()
                    return acct


def find_vanity(
    prefix: str = "",
    suffix: str = "",
    workers: int = 1,
    progress: bool = True,
):
    """Генерирует ключи, пока адрес не совпадёт с шаблоном. Возвращает LocalAccount.

    workers > 1 — пул процессов (у каждого свой os.urandom, конкуренции за
    энтропию нет); workers = 1 — прежний однопроцессорный цикл.
    """
    if workers < 1:
        raise ValueError("workers должен быть >= 1")
    p = normalize_pattern(prefix)
    s = normalize_pattern(suffix)
    total = len(p) + len(s)
    if total > 6:
        print(
            f"[i] Шаблон {total} hex-символов: в среднем ~16**{total} попыток,"
            " это может занять очень много времени",
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
            print(f"[+] Найдено за {attempts} попыток ({rate:.0f}/сек)", file=sys.stderr)
        else:
            print(f"[…] попыток: {attempts} ({rate:.0f}/сек)", file=sys.stderr)

    if workers == 1:
        while True:
            acct = Account.create()
            attempts += 1
            if matches(acct.address, p, s):
                _report(final=True)
                return acct
            now = time.monotonic()
            if now >= next_report:
                _report(final=False)
                next_report = now + PROGRESS_EVERY_SECONDS

    with multiprocessing.Pool(workers) as pool:
        while True:
            pending = [
                pool.apply_async(_search_batch, (p, s, _SEARCH_BATCH))
                for _ in range(workers * 4)
            ]
            for result in pending:
                n, found = result.get()
                attempts += n
                if found:
                    _report(final=True)
                    return Account.from_key(bytes.fromhex(found[0]))
                now = time.monotonic()
                if now >= next_report:
                    _report(final=False)
                    next_report = now + PROGRESS_EVERY_SECONDS


def build_keystore(acct, password: str) -> dict:
    """Шифрует ключ аккаунта в V3 keystore (Web3 Secret Storage, scrypt)."""
    keystore = Account.encrypt(acct.key, password)
    # eth-account кладёт checksummed-адрес; в keystore-файлах принято lowercase
    keystore["address"] = keystore["address"].lower()
    return keystore


def verify_keystore(keystore: dict, password: str, expected_address: str) -> bool:
    """Расшифровывает keystore обратно и сверяет адрес (самопроверка)."""
    try:
        key = Account.decrypt(keystore, password)
    except Exception as exc:  # неверный пароль, битый файл
        raise ValueError(f"keystore не расшифровывается: {exc}") from exc
    if Account.from_key(key).address.lower() != expected_address.lower():
        raise ValueError("адрес из keystore не совпадает с найденным")
    return True


def save_keystore(keystore: dict, directory: str) -> str:
    """Пишет keystore JSON в файл с правами 0600, имя в стиле geth."""
    os.makedirs(directory, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3] + "Z"
    path = os.path.join(directory, f"UTC--{ts}--{keystore['address']}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(keystore, f)
    return path


def prompt_password() -> str:
    """Спрашивает пароль дважды через getpass (без эха, без аргументов CLI)."""
    while True:
        pw1 = getpass.getpass("Пароль для keystore: ")
        if len(pw1) < MIN_PASSWORD_LEN:
            print(f"Минимум {MIN_PASSWORD_LEN} символов, попробуй ещё раз", file=sys.stderr)
            continue
        pw2 = getpass.getpass("Повторите пароль: ")
        if pw1 != pw2:
            print("Пароли не совпадают, попробуй ещё раз", file=sys.stderr)
            continue
        return pw1


def _hex_arg(value: str) -> str:
    try:
        return normalize_pattern(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Генератор EVM vanity-кошельков с зашифрованным keystore",
    )
    parser.add_argument("--prefix", type=_hex_arg, default="", help="начало адреса без 0x, напр. ab")
    parser.add_argument("--suffix", type=_hex_arg, default="", help="конец адреса, напр. cd")
    parser.add_argument("--count", type=int, default=1, help="сколько кошельков найти")
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"число процессов поиска (по умолчанию {DEFAULT_WORKERS} — физические ядра)",
    )
    parser.add_argument("--keystore-dir", default="keystore", help="куда сохранять файлы")
    parser.add_argument(
        "--show-privkey",
        action="store_true",
        help="показать сырой приватный ключ (по умолчанию выключено)",
    )
    parser.add_argument(
        "--walk",
        action="store_true",
        help="дешёвые шаги +1 от случайного старта (требует coincurve; намного быстрее)",
    )
    args = parser.parse_args(argv)
    if not (args.prefix or args.suffix):
        parser.error("укажи хотя бы один из --prefix / --suffix")
    if args.count < 1:
        parser.error("--count должен быть >= 1")
    if args.workers < 1:
        parser.error("--workers должен быть >= 1")

    print(BANNER, file=sys.stderr)
    password = prompt_password()

    search = find_vanity_walk if args.walk else find_vanity
    for i in range(args.count):
        acct = search(args.prefix, args.suffix, workers=args.workers)
        keystore = build_keystore(acct, password)
        verify_keystore(keystore, password, acct.address)
        path = save_keystore(keystore, args.keystore_dir)
        print(f"[{i + 1}/{args.count}] Адрес:   {acct.address}")
        print(f"         Keystore: {path} (права 0600)")
        if args.show_privkey:
            print(f"         Приватный ключ: 0x{acct.key.hex()}")
    print(
        "\n[i] Keystore — стандартный V3 (geth/MetaMask): импортируется файлом + паролем.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
