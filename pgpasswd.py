#!/usr/bin/env python3

"""Encrypt lines from STDIN as PostgreSQL SCRAM-SHA-256 passwords."""

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, ArgumentTypeError
from base64 import standard_b64encode
from contextlib import suppress
from hashlib import pbkdf2_hmac, sha256
from hmac import digest
from os import urandom
from sys import stdin

__prog__ = "pgpasswd"
__version__ = "1.0.0"
__status__ = "Release"
__author__ = "Alexander Pozlevich"
__email__ = "apozlevich@gmail.com"


def pg_scram_sha256(passwd: str, iterations: int, digest_len: int, salt_size: int) -> str:
    """Encypt password like PostgreSQL SCRAM-SHA-256."""

    def b64_encode(b: bytes) -> str:
        """Encode bytes as UTF-8 BASE64 string."""

        return standard_b64encode(b).decode(encoding="utf8")

    salt = urandom(salt_size)

    digest_key = pbkdf2_hmac(hash_name="sha256", password=passwd.encode("utf8"), salt=salt, iterations=iterations, dklen=digest_len)
    client_key = digest(key=digest_key, msg=b"Client Key", digest="sha256")
    stored_key = sha256(string=client_key).digest()
    server_key = digest(key=digest_key, msg=b"Server Key", digest="sha256")

    return f"SCRAM-SHA-256${iterations}:{b64_encode(salt)}${b64_encode(stored_key)}:{b64_encode(server_key)}"


def main() -> None:
    """Execute script."""

    def positive_int(i: int) -> int:
        """Check value is non-zero positive integer."""

        if not isinstance(i, int) or i <= 0:
            msg = "not a positive integer"
            raise ArgumentTypeError(msg)

        return i

    args_parser = ArgumentParser(
        prog=__prog__,
        description=__doc__,
        epilog=f"Written by {__author__} <{__email__}>.",
        formatter_class=lambda prog: ArgumentDefaultsHelpFormatter(prog=prog, max_help_position=34),
    )

    args_parser.add_argument("-v", "--version", action="version", version=f"{__prog__} v{__version__} ({__status__}).")
    args_parser.add_argument("-s", "--salt-size", type=positive_int, default=16, metavar="size", help="specify salt size")
    args_parser.add_argument("-d", "--digest-len", type=positive_int, default=32, metavar="length", help="specify digest length")
    args_parser.add_argument("-i", "--iterations", type=positive_int, default=4096, metavar="count", help="specify iterations count")

    cli_args = args_parser.parse_args()

    for line in stdin.readlines():
        print(  # noqa: T201 print fround
            pg_scram_sha256(
                passwd=line.strip(),
                digest_len=cli_args.digest_len,
                iterations=cli_args.iterations,
                salt_size=cli_args.salt_size,
            ),
        )


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
