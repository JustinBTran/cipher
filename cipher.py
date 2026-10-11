#!/usr/bin/env python3
"""cipher — keyphrase-based file encryption for text documents.

Encrypts with AES-256-GCM. The key is derived from your keyphrase with scrypt,
so the keyphrase is the whole ballgame: a long one is unguessable, a short one
is the way in. The same keyphrase both encrypts and decrypts.

    ./cipher.py encrypt notes.txt          -> writes notes.txt.cipher
    ./cipher.py decrypt notes.txt.cipher   -> prints the text to stdout

Decrypt prints by default and writes nothing, so reading a document leaves no
decrypted copy behind. Pass -o PATH or -w when you do want the file back:

    ./cipher.py decrypt notes.txt.cipher | less
    ./cipher.py decrypt notes.txt.cipher -w        -> writes notes.txt

Both commands prompt for the keyphrase without echoing. -k takes it inline
instead, at the cost of leaving it in your shell history.

Format of a .cipher file (the header is authenticated, so editing any of it
makes decryption fail rather than silently changing the result):

    magic      7 bytes   b"CIPHER\\x01"  -- format tag + version
    kdf_id     1 byte    1 = scrypt
    log_n      1 byte    scrypt cost, N = 2**log_n
    r          2 bytes   scrypt block size       (big endian)
    p          2 bytes   scrypt parallelism      (big endian)
    salt_len   1 byte
    salt       16 bytes  fresh random per file
    nonce      12 bytes  fresh random per file
    body       rest      AES-256-GCM ciphertext followed by its 16-byte tag

The salt is what makes the same keyphrase produce a different key for every
file, so two identical documents do not encrypt to identical bytes.

Files are encrypted in one shot, so peak memory is a few times the file size.
That is fine for documents; don't point it at a 40 GB disk image.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import secrets
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CIPHER\x01"
KDF_SCRYPT = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256
TAG_LEN = 16

# scrypt cost. log_n=17 means N=131072, which needs 128 MiB and about a second
# on a modern laptop -- slow on purpose, so guessing keyphrases stays expensive.
DEFAULT_LOG_N = 17
DEFAULT_R = 8
DEFAULT_P = 1

_FIXED_FMT = ">7sBBHHB"  # magic, kdf_id, log_n, r, p, salt_len
_FIXED_LEN = struct.calcsize(_FIXED_FMT)
HEADER_LEN = _FIXED_LEN + SALT_LEN + NONCE_LEN

SUFFIX = ".cipher"

# Short enough to brute-force is short enough to warn about.
MIN_KEYPHRASE_LEN = 10


class CipherError(Exception):
    """Anything the user should see as a clean error rather than a traceback."""


# --------------------------------------------------------------------------
# key derivation
# --------------------------------------------------------------------------


def derive_key(keyphrase: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    n = 1 << log_n
    # scrypt needs roughly 128*N*r bytes; OpenSSL refuses to go over maxmem,
    # which defaults to a stingy 32 MiB, so state the real requirement.
    maxmem = 128 * n * r * 2
    try:
        return hashlib.scrypt(
            keyphrase.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=KEY_LEN,
            maxmem=maxmem,
        )
    except (ValueError, MemoryError) as exc:
        raise CipherError(f"could not derive key (log_n={log_n}, r={r}, p={p}): {exc}")


# --------------------------------------------------------------------------
# header
# --------------------------------------------------------------------------


def pack_header(log_n: int, r: int, p: int, salt: bytes, nonce: bytes) -> bytes:
    return (
        struct.pack(_FIXED_FMT, MAGIC, KDF_SCRYPT, log_n, r, p, len(salt))
        + salt
        + nonce
    )


def unpack_header(blob: bytes) -> tuple[int, int, int, bytes, bytes]:
    if len(blob) < HEADER_LEN:
        raise CipherError("file is too short to be a cipher file")

    magic, kdf_id, log_n, r, p, salt_len = struct.unpack_from(_FIXED_FMT, blob)

    if magic[:6] != MAGIC[:6]:
        raise CipherError("not a cipher file (bad magic bytes)")
    if magic[6] != MAGIC[6]:
        raise CipherError(
            f"file uses format version {magic[6]}, this tool speaks {MAGIC[6]}"
        )
    if kdf_id != KDF_SCRYPT:
        raise CipherError(f"unknown key-derivation id {kdf_id}")
    if salt_len != SALT_LEN:
        raise CipherError(f"unexpected salt length {salt_len}")
    if not 1 <= log_n <= 24 or r < 1 or p < 1:
        raise CipherError("header declares nonsensical scrypt parameters")

    salt = blob[_FIXED_LEN : _FIXED_LEN + salt_len]
    nonce = blob[_FIXED_LEN + salt_len : HEADER_LEN]
    return log_n, r, p, salt, nonce


# --------------------------------------------------------------------------
# core
# --------------------------------------------------------------------------


def encrypt_bytes(
    plaintext: bytes,
    keyphrase: str,
    log_n: int = DEFAULT_LOG_N,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = pack_header(log_n, r, p, salt, nonce)
    key = derive_key(keyphrase, salt, log_n, r, p)
    # The header goes in as associated data: it is not secret, but it is signed.
    body = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + body


def decrypt_bytes(blob: bytes, keyphrase: str) -> bytes:
    log_n, r, p, salt, nonce = unpack_header(blob)
    header, body = blob[:HEADER_LEN], blob[HEADER_LEN:]
    if len(body) < TAG_LEN:
        raise CipherError("file is truncated (no room for the authentication tag)")
    key = derive_key(keyphrase, salt, log_n, r, p)
    try:
        return AESGCM(key).decrypt(nonce, body, header)
    except InvalidTag:
        raise CipherError("wrong keyphrase, or the file has been modified or corrupted")


# --------------------------------------------------------------------------
# file plumbing
# --------------------------------------------------------------------------


def write_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write via a temp file in the same directory, then rename into place.

    A crash mid-write leaves the original alone instead of a half-file.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            os.unlink(tmp)
            raise
        os.replace(tmp, path)
    except OSError as exc:
        raise CipherError(f"could not write {path}: {exc}")


def default_output(src: Path, decrypting: bool) -> Path:
    if decrypting:
        if src.suffix == SUFFIX:
            return src.with_suffix("")
        return src.with_name(src.name + ".decrypted")
    return src.with_name(src.name + SUFFIX)


def read_file(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CipherError(f"could not read {path}: {exc}")


# --------------------------------------------------------------------------
# keyphrase input
# --------------------------------------------------------------------------


def get_keyphrase(args: argparse.Namespace, confirm: bool) -> str:
    """Resolve the keyphrase from -k, --keyphrase-env, --keyphrase-file, or a prompt.

    argparse has already enforced that at most one source is given.
    """
    if args.keyphrase:
        # Anything on the command line lands in shell history and is visible in
        # `ps` to other users on the machine. Fine for scratch files, worth
        # knowing about for real ones.
        warn("a keyphrase passed with -k is saved in your shell history")
        check_length(args.keyphrase)
        return args.keyphrase

    if args.keyphrase_file:
        path = Path(args.keyphrase_file)
        try:
            # Only the first line, minus its newline -- editors love adding one.
            phrase = path.read_text(encoding="utf-8").split("\n", 1)[0].rstrip("\r")
        except OSError as exc:
            raise CipherError(f"could not read keyphrase file {path}: {exc}")
        if not phrase:
            raise CipherError(f"keyphrase file {path} is empty")
        check_length(phrase)
        return phrase

    if args.keyphrase_env:
        phrase = os.environ.get(args.keyphrase_env)
        if not phrase:
            raise CipherError(
                f"environment variable {args.keyphrase_env} is unset or empty"
            )
        check_length(phrase)
        return phrase

    if not sys.stdin.isatty():
        raise CipherError(
            "no terminal to prompt on; pass -k, --keyphrase-env, or --keyphrase-file"
        )

    return prompt_keyphrase(confirm)


def prompt_keyphrase(confirm: bool) -> str:
    while True:
        phrase = getpass.getpass("Keyphrase: ")
        if not phrase:
            print("Empty keyphrase; try again.", file=sys.stderr)
            continue
        if confirm:
            # Only enforced at the prompt, where retrying is free. Scripted
            # callers get a warning instead of a hard stop.
            if len(phrase) < MIN_KEYPHRASE_LEN:
                print(
                    f"Use at least {MIN_KEYPHRASE_LEN} characters -- this keyphrase "
                    "is the only thing protecting the file.",
                    file=sys.stderr,
                )
                continue
            if phrase != getpass.getpass("Confirm keyphrase: "):
                print("Keyphrases did not match; try again.", file=sys.stderr)
                continue
        return phrase


def check_length(phrase: str) -> None:
    if len(phrase) < MIN_KEYPHRASE_LEN:
        warn(
            f"keyphrase is only {len(phrase)} characters; "
            f"{MIN_KEYPHRASE_LEN} or more is much harder to guess"
        )


def warn(message: str) -> None:
    print(f"cipher: warning: {message}", file=sys.stderr)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def validate_sources(files: list[str]) -> list[Path]:
    sources = [Path(s) for s in files]
    for src in sources:
        if not src.exists():
            raise CipherError(f"{src} does not exist")
        if not src.is_file():
            raise CipherError(f"{src} is not a regular file")
    return sources


def resolve_outputs(
    args: argparse.Namespace, sources: list[Path], decrypting: bool
) -> list[tuple[Path, Path]]:
    if args.output:
        if len(sources) != 1:
            raise CipherError("-o/--output only works with a single input file")
        pairs = [(sources[0], Path(args.output))]
    else:
        pairs = [(src, default_output(src, decrypting)) for src in sources]

    for src, dst in pairs:
        if dst.resolve() == src.resolve():
            raise CipherError(f"refusing to write {dst} over its own input")
        if dst.exists() and not args.force:
            raise CipherError(f"{dst} already exists (pass --force to overwrite)")

    return pairs


def cmd_encrypt(args: argparse.Namespace) -> int:
    sources = validate_sources(args.files)
    pairs = resolve_outputs(args, sources, decrypting=False)

    # An empty input is almost always a mistake: a typo'd filename, or a file
    # that moved. Encrypting it yields a 58-byte vault holding nothing, which
    # looks like success until the day you need the contents -- and with
    # --remove-source it would delete the real file you meant to protect.
    # Checked before prompting so the keyphrase is not typed for nothing.
    if not args.allow_empty:
        empty = [str(src) for src, _ in pairs if src.stat().st_size == 0]
        if empty:
            names = ", ".join(empty)
            raise CipherError(
                f"{names} {'is' if len(empty) == 1 else 'are'} empty -- nothing to "
                "encrypt. Check the filename, or pass --allow-empty if you meant it."
            )

    # Confirm only matters for a typed keyphrase: a typo you cannot see would
    # lock the file forever.
    keyphrase = get_keyphrase(args, confirm=True)

    for src, dst in pairs:
        blob = encrypt_bytes(read_file(src), keyphrase, args.log_n, args.r, args.p)
        write_atomic(dst, blob)
        print(f"{src} -> {dst}", file=sys.stderr)
        if args.remove_source:
            try:
                src.unlink()
                print(f"  removed {src}", file=sys.stderr)
            except OSError as exc:
                raise CipherError(f"encrypted fine, but could not remove {src}: {exc}")

    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Print the plaintext by default; only touch the disk if asked to.

    Reading a document should not leave a decrypted copy lying around, so
    writing one is opt-in via -o PATH or -w.
    """
    sources = validate_sources(args.files)

    if args.output or args.write:
        pairs = resolve_outputs(args, sources, decrypting=True)
    else:
        pairs = [(src, None) for src in sources]

    keyphrase = get_keyphrase(args, confirm=False)

    for src, dst in pairs:
        plaintext = decrypt_bytes(read_file(src), keyphrase)
        if dst is None:
            emit_plaintext(plaintext, src)
        else:
            write_atomic(dst, plaintext)
            # stderr, so stdout stays usable as a pure data channel
            print(f"{src} -> {dst}", file=sys.stderr)

    return 0


def emit_plaintext(data: bytes, src: Path) -> None:
    """Write plaintext to stdout byte-for-byte.

    No trailing newline is added: `cipher decrypt f | sha256sum` has to match
    the original file's hash, and inventing a byte would break that.
    """
    if sys.stdout.isatty() and looks_binary(data):
        raise CipherError(
            f"{src} decrypts to binary data; pass -o PATH, or redirect stdout"
        )
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def looks_binary(data: bytes) -> bool:
    """Only used to avoid blasting control codes at a terminal. A pipe gets the
    bytes regardless -- the caller may well be expecting binary."""
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def cmd_info(args: argparse.Namespace) -> int:
    """Show what is readable without the keyphrase -- which is only metadata."""
    for name in args.files:
        path = Path(name)
        blob = read_file(path)
        log_n, r, p, salt, _nonce = unpack_header(blob)
        payload = max(len(blob) - HEADER_LEN - TAG_LEN, 0)
        mib = 128 * (1 << log_n) * r // (1 << 20)
        print(f"{path}")
        print(f"  format      CIPHER v{MAGIC[6]}, AES-256-GCM")
        print(f"  kdf         scrypt N=2^{log_n} r={r} p={p}  (~{mib} MiB)")
        print(f"  salt        {salt.hex()}")
        print(f"  plaintext   {payload} bytes")
    return 0


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipher",
        description="Encrypt and decrypt files with a keyphrase (AES-256-GCM).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_keyphrase_flags(sp: argparse.ArgumentParser) -> None:
        group = sp.add_mutually_exclusive_group()
        group.add_argument(
            "-k",
            "--keyphrase",
            metavar="PHRASE",
            help="the keyphrase itself (careful: lands in your shell history)",
        )
        group.add_argument(
            "--keyphrase-env",
            metavar="VAR",
            help="read the keyphrase from this environment variable",
        )
        group.add_argument(
            "--keyphrase-file",
            metavar="PATH",
            help="read the keyphrase from the first line of this file",
        )

    enc = sub.add_parser("encrypt", help="encrypt one or more files")
    enc.add_argument("files", nargs="+")
    enc.add_argument("-o", "--output", help="output path (single input only)")
    enc.add_argument(
        "-f", "--force", action="store_true", help="overwrite existing output"
    )
    enc.add_argument(
        "--remove-source",
        action="store_true",
        help="delete the plaintext after a successful encrypt "
        "(does not wipe the underlying disk blocks)",
    )
    enc.add_argument(
        "--allow-empty",
        action="store_true",
        help="encrypt a zero-byte file instead of refusing (normally a typo'd name)",
    )
    enc.add_argument(
        "--log-n",
        type=int,
        default=DEFAULT_LOG_N,
        metavar="N",
        help=f"scrypt cost exponent, higher is slower and stronger (default {DEFAULT_LOG_N})",
    )
    enc.add_argument("--r", type=int, default=DEFAULT_R, help=argparse.SUPPRESS)
    enc.add_argument("--p", type=int, default=DEFAULT_P, help=argparse.SUPPRESS)
    add_keyphrase_flags(enc)
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser(
        "decrypt",
        help="decrypt one or more files, printing to stdout",
        description="Prints the plaintext to stdout. Pass -o or -w to write a file instead.",
    )
    dec.add_argument("files", nargs="+")
    dest = dec.add_mutually_exclusive_group()
    dest.add_argument("-o", "--output", help="write to this path (single input only)")
    dest.add_argument(
        "-w",
        "--write",
        action="store_true",
        help="write to the default name (strips the .cipher suffix)",
    )
    dec.add_argument(
        "-f", "--force", action="store_true", help="overwrite existing output"
    )
    add_keyphrase_flags(dec)
    dec.set_defaults(func=cmd_decrypt)

    info = sub.add_parser("info", help="show the header of an encrypted file")
    info.add_argument("files", nargs="+")
    info.set_defaults(func=cmd_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CipherError as exc:
        print(f"cipher: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ncipher: cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
