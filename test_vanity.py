"""Tests for vanity_key.py and vanity_seed.py (written first: RED -> GREEN)."""

import pytest

HEX_ADDR = "0xABCdef1234567890ABCdef1234567890ABCdef12"


# ---------------------------------------------------------------- vanity_key

def test_key_normalize_strips_0x_and_lowercases():
    from vanity_key import normalize_pattern

    assert normalize_pattern("0xAbC") == "abc"
    assert normalize_pattern("AbC") == "abc"


def test_key_normalize_rejects_non_hex():
    from vanity_key import normalize_pattern

    with pytest.raises(ValueError):
        normalize_pattern("xyz")


def test_key_matches_prefix_suffix_case_insensitive():
    from vanity_key import matches

    assert matches(HEX_ADDR, "0xabc", "def12")
    assert matches(HEX_ADDR, "", "")
    assert not matches(HEX_ADDR, "abd", "")
    assert not matches(HEX_ADDR, "", "def13")


def test_key_find_vanity_returns_matching_account():
    from vanity_key import find_vanity

    acct = find_vanity(prefix="0")
    assert acct.address.lower().startswith("0x0")


def test_key_build_keystore_roundtrip():
    from eth_account import Account

    from vanity_key import build_keystore, verify_keystore

    acct = Account.create()
    ks = build_keystore(acct, "correct horse battery staple")
    assert ks["address"] == acct.address.lower().replace("0x", "")
    assert verify_keystore(ks, "correct horse battery staple", acct.address)

    with pytest.raises(ValueError):
        verify_keystore(ks, "wrong password", acct.address)


def test_key_main_rejects_bad_pattern():
    from vanity_key import main

    with pytest.raises(SystemExit) as exc:
        main(["--prefix", "zz"])
    assert exc.value.code != 0


# --------------------------------------------------------------- vanity_seed

def test_seed_generate_mnemonic_lengths_and_checksum():
    from mnemonic import Mnemonic

    from vanity_seed import generate_mnemonic

    m = Mnemonic("english")
    ph24 = generate_mnemonic(24)
    ph12 = generate_mnemonic(12)
    assert len(ph24.split()) == 24 and m.check(ph24)
    assert len(ph12.split()) == 12 and m.check(ph12)


def test_seed_generate_mnemonic_invalid_word_count():
    from vanity_seed import generate_mnemonic

    with pytest.raises(ValueError):
        generate_mnemonic(13)


def test_seed_address_from_mnemonic_deterministic():
    from vanity_seed import address_from_mnemonic, generate_mnemonic

    ph = generate_mnemonic(12)
    assert address_from_mnemonic(ph) == address_from_mnemonic(ph)


def test_seed_find_vanity_returns_valid_phrase_address_pair():
    from vanity_seed import address_from_mnemonic, find_vanity_seed

    phrase, address = find_vanity_seed(prefix="0")
    assert address.lower().startswith("0x0")
    # фраза действительно выводится в найденный адрес (независимая сверка)
    assert address_from_mnemonic(phrase) == address


def test_seed_main_rejects_bad_pattern():
    from vanity_seed import main

    with pytest.raises(SystemExit) as exc:
        main(["--suffix", "zz"])
    assert exc.value.code != 0


# ------------------------------------------------------------ multiprocessing

def test_key_find_vanity_parallel_returns_matching_account():
    from vanity_key import find_vanity

    acct = find_vanity(prefix="0", workers=4)
    assert acct.address.lower().startswith("0x0")


def test_key_find_vanity_rejects_bad_workers():
    from vanity_key import find_vanity

    with pytest.raises(ValueError):
        find_vanity(prefix="0", workers=0)


def test_seed_find_vanity_parallel_returns_valid_pair():
    from vanity_seed import address_from_mnemonic, find_vanity_seed

    phrase, address = find_vanity_seed(prefix="0", workers=4)
    assert address.lower().startswith("0x0")
    assert address_from_mnemonic(phrase) == address


def test_seed_find_vanity_rejects_bad_workers():
    from vanity_seed import find_vanity_seed

    with pytest.raises(ValueError):
        find_vanity_seed(prefix="0", workers=0)


# ---------------------------------------------------------------- random walk

def test_walk_addresses_match_full_derivation():
    """Инкрементальное блуждание обязано давать те же адреса, что честная деривация k·G."""
    from eth_account import Account

    from vanity_key import _random_start, walk_addresses

    start = _random_start()
    for i, (addr, k) in enumerate(walk_addresses(start, 6)):
        assert k == start + i
        # walk даёт lowercase, Account.address — EIP-55: адрес один и тот же
        assert addr.lower() == Account.from_key(k.to_bytes(32, "big")).address.lower()


def test_random_start_in_curve_range():
    from vanity_key import SECP256K1_N, _random_start

    for _ in range(20):
        k = _random_start()
        assert 1 <= k < SECP256K1_N


def test_find_vanity_walk_returns_verified_account():
    from vanity_key import find_vanity_walk

    acct = find_vanity_walk(prefix="0")
    assert acct.address.lower().startswith("0x0")


def test_find_vanity_walk_parallel():
    from vanity_key import find_vanity_walk

    acct = find_vanity_walk(prefix="0", workers=4)
    assert acct.address.lower().startswith("0x0")


# ------------------------------------------------- seed: scan-indexes mode

def test_seed_scan_address_at_index_matches_full_path():
    """Ручной BIP-32 узел + индекс обязан совпадать с официальной деривацией eth-account."""
    from eth_account import Account

    from vanity_seed import _bip32_node, address_at_index, generate_mnemonic

    Account.enable_unaudited_hdwallet_features()
    ph = generate_mnemonic(12)
    node = _bip32_node(ph)
    for i in (0, 1, 7, 1234):
        addr, _k = address_at_index(node, i)
        full = Account.from_mnemonic(ph, account_path=f"m/44'/60'/0'/0/{i}").address
        assert addr.lower() == full.lower()


def test_seed_scan_returns_indexed_pair():
    from eth_account import Account

    from vanity_seed import find_vanity_seed_scan, generate_mnemonic

    Account.enable_unaudited_hdwallet_features()
    phrase, index, address = find_vanity_seed_scan(prefix="0", words=12, max_index=2000)
    assert address.lower().startswith("0x0")
    assert 0 <= index < 2000
    full = Account.from_mnemonic(phrase, account_path=f"m/44'/60'/0'/0/{index}").address
    assert full.lower() == address


def test_seed_scan_parallel():
    from vanity_seed import find_vanity_seed_scan

    _phrase, _index, address = find_vanity_seed_scan(
        prefix="0", words=12, max_index=2000, workers=4
    )
    assert address.lower().startswith("0x0")


def test_seed_scan_rejects_bad_max_index():
    from vanity_seed import find_vanity_seed_scan

    with pytest.raises(ValueError):
        find_vanity_seed_scan(prefix="0", max_index=0)
