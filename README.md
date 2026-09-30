# EVM Vanity Wallet Generator

[Читать на русском](README_RU.md)

Two security-focused scripts that generate Ethereum / EVM-compatible wallets
whose **address starts and/or ends with characters you choose** (a "vanity"
address):

- **`vanity_key.py`** — generates a random private key and immediately encrypts
  it into a standard **V3 keystore** file (Web3 Secret Storage, scrypt). The raw
  key is never printed or written in plaintext.
- **`vanity_seed.py`** — generates **BIP-39 seed phrases** (12–24 words). The
  found address always sits at index `0` of the standard derivation path
  `m/44'/60'/0'/0/0`, so the phrase imports as-is into MetaMask, Ledger, Trezor,
  Trust Wallet, etc. An optional fast mode scans many indexes per phrase.

Both scripts are built for wallets that may hold **real funds**: keys come only
from `os.urandom` (kernel CSPRNG), passwords are asked via `getpass`, keystore
files are written with `0600` permissions, and every result is re-verified
before being reported.

## Table of contents

- [Installation](#installation)
- [Offline machine (recommended for real funds)](#offline-machine-recommended-for-real-funds)
- [Quick start](#quick-start)
- [Search modes](#search-modes)
- [Speed expectations](#speed-expectations)
- [`vanity_key.py` reference](#vanity_keypy-reference)
- [`vanity_seed.py` reference](#vanity_seedpy-reference)
- [Working with keystore files](#working-with-keystore-files)
- [How the search works](#how-the-search-works)
- [Security notes](#security-notes)
- [Tests](#tests)

## Installation

Python 3.10+ is required (3.12 tested).

```bash
cd vanity-wallet
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt

# or with uv (faster):
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python --require-hashes -r requirements.txt
```

Dependencies are fully locked with hashes:

| File | Contents |
|------|----------|
| `requirements.in` | direct runtime dependencies: `eth-account`, `mnemonic`, `coincurve` |
| `requirements.txt` | full runtime lock (all transitive packages) with `sha256` hashes |
| `requirements-dev.in` / `requirements-dev.txt` | `pytest` for running the tests |

`--require-hashes` makes pip reject any file whose hash does not match the
lock, so a tampered or substituted package fails the install. To update the
lock, edit the `.in` file and regenerate:

```bash
uv pip compile requirements.in --universal --python-version 3.10 --generate-hashes -o requirements.txt
uv pip compile requirements-dev.in --universal --python-version 3.10 --generate-hashes -o requirements-dev.txt
```

> `coincurve` (C bindings for libsecp256k1) is optional but strongly
> recommended — without it `eth-keys` falls back to a pure-Python backend that
> is ~20x slower. It is required for the `--walk` and `--scan-indexes` modes.

## Offline machine (recommended for real funds)

`pip install` needs network access, so download the dependencies in advance and
carry them on a USB stick (same OS/architecture):

```bash
# on the online machine:
mkdir wheels
.venv/bin/pip download -r requirements.txt -d wheels

# on the air-gapped machine:
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links /media/usb/wheels --require-hashes -r requirements.txt
```

Hashes are checked on both machines, so the wheels cannot be silently swapped
on the USB stick. `pytest` is not needed on the offline machine.

Run the search with networking disabled. Write the seed phrase on paper; copy
the keystore file out with the USB stick. The phrase/keystore **is** the backup
— the machine can be destroyed afterwards.

## Quick start

```bash
# Private key → encrypted keystore; address starts with "ab", ends with "cd":
.venv/bin/python vanity_key.py --prefix ab --suffix cd

# Fastest key mode (random start + cheap +1 steps):
.venv/bin/python vanity_key.py --walk --workers 14 --prefix dead --suffix beef

# 24-word seed phrase, address starts with "ab":
.venv/bin/python vanity_seed.py --prefix ab

# Fast seed mode (one phrase, many indexes — see caveats):
.venv/bin/python vanity_seed.py --scan-indexes --workers 14 --prefix ab
```

You will be prompted for a keystore password (`getpass`, asked twice,
minimum 8 characters, never a CLI argument). Files land in `./keystore/` with
`0600` permissions. The seed phrase is printed **once** — copy it to paper.

## Search modes

| Mode | Script / flag | One attempt costs | Best for |
|------|---------------|-------------------|----------|
| Random keys | `vanity_key.py` | full keygen (`os.urandom` + `k·G`) | simplest, max paranoia |
| Random walk | `vanity_key.py --walk` | one point addition `P += G` | fastest overall (~7x) |
| Random phrases | `vanity_seed.py` | PBKDF2 (2048 iters) + derivation | phrase works in every wallet |
| Index scan | `vanity_seed.py --scan-indexes` | one BIP-32 CKD step | fast **and** phrase-based, needs custom path |

All four are probabilistically equivalent per attempt: every candidate address
matches the pattern with probability `16^-(len(prefix)+len(suffix))`, so the
expected number of attempts is `16^n` for an `n`-character pattern. Adding one
hex character multiplies the expected time by 16.

## Speed expectations

Measured on a Ryzen laptop (8 cores / 16 threads, 14 worker processes,
`coincurve` installed). Your numbers will differ.

| Pattern length | Attempts (avg) | `--walk` ~680k/s | random key ~98k/s | `--scan-indexes` ~113k/s | seed phrase ~1.7k/s |
|----------------|----------------|------------------|-------------------|--------------------------|----------------------|
| 4 hex chars    | 65,536         | instant          | ~0.7 s            | ~0.6 s                   | ~40 s                |
| 5              | 1,048,576      | ~1.5 s           | ~11 s             | ~9 s                     | ~10 min              |
| 6              | 16,777,216     | ~25 s            | ~2.9 min          | ~2.5 min                 | ~2.7 h               |
| 7              | 268,435,456    | ~6.6 min         | ~46 min           | ~40 min                  | ~1.8 days            |
| 8              | 4,294,967,296  | ~1.8 h           | ~12 h             | ~10.6 h                  | ~29 days             |

Notes:

- The reported rate is **cumulative** since process start; short runs
  underestimate steady-state throughput.
- Default `--workers` is half the logical CPUs (physical cores). On
  SMT/HyperThreading machines the sweet spot is typically a bit above the
  physical core count (e.g. 14 on a 8C/16T machine); values above the logical
  CPU count only add contention.
- The process is **memoryless**: you can stop and restart at any time, split
  the search across nights or machines — statistically it is the same as one
  continuous run.

## `vanity_key.py` reference

```
.venv/bin/python vanity_key.py --prefix HEX [--suffix HEX] [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--prefix` | *(empty)* | Required characters at the start of the address, without `0x`. Hex digits `0-9a-f`, case-insensitive. |
| `--suffix` | *(empty)* | Required characters at the end of the address. |
| `--count N` | `1` | How many matching wallets to find (each gets its own keystore file). |
| `--workers N` | physical cores | Number of worker processes. `1` = single-process loop. |
| `--keystore-dir DIR` | `./keystore` | Output directory for keystore files. |
| `--show-privkey` | off | Also print the raw private key. Off by default. |
| `--walk` | off | Fast mode: one random 256-bit starting key, then cheap `+1` steps (`P += G`, one point addition instead of a full `k·G`). Requires `coincurve`. |

At least one of `--prefix` / `--suffix` must be given (exit code 2 otherwise).

Behavior:

- Each found key is encrypted into a **V3 keystore** (scrypt, `n=262144`) with
  the password you typed; the file is named `UTC--<timestamp>--<address>`
  (geth convention) and written with mode `0600`.
- Before saving, the keystore is **decrypted back and the address is verified**
  — a corrupt file or mistyped password cannot slip through silently.
- In `--walk` mode the starting point is always drawn uniformly from
  `[1, n-1]` via `os.urandom` (rejection sampling). The found key is re-derived
  the honest way (`k·G` from scratch) and both address and pattern are
  re-checked. **Never** replace the random start with a "nice" number — small
  or predictable starting points produce compromised keys that bots sweep.

## `vanity_seed.py` reference

```
.venv/bin/python vanity_seed.py --prefix HEX [--suffix HEX] [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--prefix` | *(empty)* | Required characters at the start of the address, without `0x`, case-insensitive. |
| `--suffix` | *(empty)* | Required characters at the end of the address. |
| `--count N` | `1` | How many wallets to find. |
| `--workers N` | physical cores | Number of worker processes. |
| `--words {12,15,18,21,24}` | `24` | Mnemonic length. 12 = 128 bits of entropy, 24 = 256 bits. 12 and 24 are accepted by every wallet UI. |
| `--bip39-passphrase` | off | Prompt for a BIP-39 passphrase (the "25th word") via `getpass`. Adds a password factor to derivation; not supported equally by all wallets, hence opt-in. |
| `--save-keystore` | off | Additionally save the private key derived from the found phrase into an encrypted V3 keystore (asks for a separate keystore password). |
| `--keystore-dir DIR` | `./keystore` | Output directory for keystore files. |
| `--scan-indexes` | off | Fast mode: scan up to `--max-index` addresses `m/44'/60'/0'/0/i` per phrase. Requires `coincurve`. |
| `--max-index N` | `10000` | Per-phrase index limit in `--scan-indexes` mode. |

Behavior:

- Default mode: every attempt is a brand-new mnemonic (English BIP-39 wordlist,
  entropy from `os.urandom`); the reported address is index `0` of
  `m/44'/60'/0'/0/0`, so the phrase imports anywhere with no extra settings.
- The phrase is printed **once**. Copy it to paper before closing the terminal.
- `--scan-indexes` mode: PBKDF2 is paid once per phrase, then each index is a
  cheap BIP-32 step (~66x faster than phrase-per-attempt). The found
  `(phrase, index)` pair is verified against the official `eth-account`
  derivation over the full path. **Caveat**: the found index is usually in the
  hundreds or thousands — MetaMask would require manually adding that many
  accounts, so use a wallet with custom derivation paths (Rabby, MEW) or import
  the derived key via `--save-keystore`.

## Working with keystore files

The keystore is the standard **Web3 Secret Storage V3** JSON (the same format
geth and MetaMask produce). The file alone is useless without the password:
scrypt derives the encryption key, AES-128-CTR encrypts the private key, and a
keccak-based MAC rejects wrong passwords.

- **MetaMask**: add account → import JSON file → enter the keystore password.
- **geth**: `geth account import keystore/UTC--...`
- **Python**: 
  ```python
  import json
  from eth_account import Account
  with open("keystore/UTC--...") as f:
      key = Account.decrypt(json.load(f), "your-password")
  print("0x" + key.hex())
  ```
- File + password together are the backup. A lost password means
  unrecoverable funds; keep the password and the file stored separately.

## How the search works

One attempt: draw 32 random bytes (the private key) → compute the public key
`K = k·G` on secp256k1 → address = last 20 bytes of `keccak256(K)` → string
comparison against prefix/suffix → repeat.

There is no "getting closer": each attempt is an independent lottery ticket
with probability `16^-n` of matching, which is why expected attempts are `16^n`
and why the process is memoryless. The one-wayness of `k·G` and keccak is also
why brute force is the only known way to obtain a vanity key — you cannot
compute a key backwards from a desired address.

For parallelism, each worker process runs an independent stream from the
kernel CSPRNG (`getrandom(2)`; no userspace PRNG state, so forked workers never
repeat each other's output).

## Security notes

- **Generate on a clean, preferably offline machine.** A container on your own
  offline machine is a reasonable compromise; a VM with snapshots is not
  (restoring a snapshot replays the guest RNG state); a remote server puts the
  key in someone else's RAM.
- Keys/phrases exist in process memory for a while (Python does not zero
  memory) and on your screen once. `clear` the terminal afterwards.
- Passwords are never accepted as CLI arguments (visible in `ps`); `getpass`
  only.
- Historical context: the 2022 Profanity incident (~$3.3M stolen) was caused by
  a 32-bit RNG seed, not by vanity search itself. These scripts never weaken
  entropy for speed — every key or phrase is full-strength `os.urandom`.
- Collision is not a threat: for another generator to produce your exact key
  by chance is ~2^-256 (2^-128 for 12-word phrases) per attempt — beyond any
  physical analogy. Real risks are RNG quality, dependency compromise, and key
  leakage, in that order of likelihood.

## Tests

```bash
uv pip install --python .venv/bin/python --require-hashes -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

23 tests cover pattern matching, keystore round-trips, mnemonic generation and
checksums, derivation determinism, the incremental-walk vs full-derivation
equivalence, the manual BIP-32 CKD vs official `eth-account` path equivalence,
and single/parallel search for all modes.
