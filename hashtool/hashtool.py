#!/usr/bin/env python3

from __future__ import annotations

import binascii
import hashlib
import os
import sys
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal
from tempfile import _TemporaryFileWrapper
from typing import BinaryIO

signal(SIGPIPE, SIG_DFL)

# Constants
BLOCK_SIZE: int = 65536  # 64KB for better performance


class IncorrectHashError(ValueError):
    pass


class Digest:
    """Immutable hash digest wrapper with validation."""

    __slots__ = ("algorithm", "digest", "hexdigest", "digestlen", "hexdigestlen")

    def __init__(
        self,
        algorithm: str,
        digest: bytes | None = None,
        preimage: bytes | None = None,
    ) -> None:
        if (digest is None) == (preimage is None):
            raise ValueError("Exactly one of digest or preimage must be provided")

        self.algorithm = algorithm

        if preimage is not None:
            digest = hashlib.new(algorithm, preimage).digest()

        assert digest is not None
        self.digest = digest
        self.hexdigest = digest.hex()
        self.digestlen = hashlib.new(algorithm).digest_size
        self.hexdigestlen = self.digestlen * 2

        if len(self.digest) != self.digestlen:
            raise ValueError(
                f"Digest {self.hexdigest} is {len(self.digest)} bytes, "
                f"expected {self.digestlen} for {algorithm}"
            )

    def __str__(self) -> str:
        return f"<Digest {self.algorithm}:{self.hexdigest}>"

    def __repr__(self) -> str:
        return str(self)

    def __len__(self) -> int:
        return len(self.digest)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Digest):
            return NotImplemented
        return self.digest == other.digest

    def __hash__(self) -> int:
        return hash(self.digest)


@lru_cache(maxsize=1)
def get_available_algorithms() -> list[str]:
    """Get list of usable hash algorithms, filtering out problematic ones."""
    excluded = {
        "ripemd160",
        "sha512_224",
        "sm3",
        "whirlpool",
        "md5-sha1",
        "sha512_256",
        "md4",
        "mdc2",
    }
    algs = []
    for alg in hashlib.algorithms_available:
        if alg in excluded or alg.startswith("shake_"):
            continue
        if alg.startswith("sha3-"):
            alg = alg.replace("-", "_")
        algs.append(alg)
    return sorted(algs)


def emptyhash(algorithm: str) -> str:
    """Return hex digest of empty bytes for given algorithm."""
    return hashlib.new(algorithm, b"").hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha3_256") -> bytes:
    """Hash bytes and return digest."""
    return hashlib.new(algorithm, data).digest()


def hash_str(string: str, algorithm: str = "sha3_256") -> bytes:
    """Hash string (UTF-8 encoded) and return digest."""
    return hash_bytes(string.encode("utf8"), algorithm)


def multi_hash_bytes(data: bytes, algorithms: Iterable[str]) -> dict[str, bytes]:
    """Hash data with multiple algorithms, return dict of digests."""
    return {alg: hashlib.new(alg, data).digest() for alg in algorithms}


def multi_hash_str(string: str, algorithms: Iterable[str]) -> dict[str, bytes]:
    """Hash string with multiple algorithms, return dict of digests."""
    return multi_hash_bytes(string.encode("utf8"), algorithms)


def hash_readable(
    handle: BinaryIO,
    algorithm: str,
    block_size: int = BLOCK_SIZE,
    tmp: _TemporaryFileWrapper | None = None,
) -> bytes:
    """Hash a readable binary file handle."""
    hasher = hashlib.new(algorithm)
    while chunk := handle.read(block_size):
        hasher.update(chunk)
        if tmp:
            tmp.write(chunk)

    if tmp:
        if isinstance(tmp.file.name, int):
            os.posix_fadvise(
                tmp.file.name,
                0,
                0,
                os.POSIX_FADV_DONTNEED,
            )
        tmp.close()

    return hasher.digest()


def hash_file(
    path: Path | str,
    algorithm: str,
    block_size: int = BLOCK_SIZE,
    tmp: _TemporaryFileWrapper | None = None,
) -> bytes:
    """Hash a file and return digest bytes."""
    path = Path(path).expanduser()
    fd = os.open(path, os.O_RDONLY)

    try:
        with os.fdopen(fd, 'rb') as fh:
            digest = hash_readable(fh, algorithm, block_size, tmp)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        return digest
    except Exception:
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        except:
            pass
        raise




def multi_hash_file(
    path: Path | str,
    algorithms: Iterable[str],
    block_size: int = BLOCK_SIZE,
) -> dict[str, bytes]:
    """Hash a file with multiple algorithms efficiently (single pass)."""
    path = Path(path).expanduser()
    hashers = {alg: hashlib.new(alg) for alg in algorithms}

    fd = os.open(path, os.O_RDONLY)
    try:
        with os.fdopen(fd, "rb") as fh:
            while chunk := fh.read(block_size):
                for hasher in hashers.values():
                    hasher.update(chunk)
        os.posix_fadvise(
            fd,
            0,
            0,
            os.POSIX_FADV_DONTNEED,
        )
    except Exception:
        try:
            os.posix_fadvise(
                fd,
                0,
                0,
                os.POSIX_FADV_DONTNEED,
            )
            os.close(fd)
        except:
            pass
        raise

    return {alg: hasher.digest() for alg, hasher in hashers.items()}


def rhash_file(
    path: Path | str,
    algorithms: Iterable[str],
    disable_locking: bool = False,
) -> dict[str, Digest]:
    """
    Hash file using external rhash tool for better performance.
    Returns dict of Digest objects keyed by algorithm name.
    Requires: pip install hs advisory-lock
    """
    import hs
    from advisory_lock import AdvisoryLock

    path = Path(path).expanduser().resolve()
    algorithms = list(algorithms)
    if not algorithms:
        raise ValueError("No algorithms specified")

    # Map algorithm names to rhash flags and format specifiers
    alg_map = {
        "sha3_256": ("--sha3-256", "sha3_256:%{sha3-256}"),
        "sha256": ("--sha256", "sha256:%{sha-256}"),
        "sha1": ("--sha1", "sha1:%{sha1}"),
    }

    cmd = hs.Command("rhash")
    format_parts = []

    for alg in algorithms:
        if alg not in alg_map:
            raise NotImplementedError(f"rhash support not implemented for {alg}")
        flag, fmt = alg_map[alg]
        cmd.bake(flag)
        format_parts.append(fmt)

    cmd.bake(f"--printf={' '.join(format_parts)}")
    cmd.bake(path.as_posix())

    def run_rhash() -> str:
        result = cmd()
        if not result:
            raise RuntimeError("rhash returned empty result")
        return result

    if disable_locking:
        output = run_rhash()
    else:
        with AdvisoryLock(
            path=path,
            file_exists=True,
            open_read=True,
            open_write=False,
            flock=True,
        ):
            output = run_rhash()

    # Parse output: "alg1:hexdigest1 alg2:hexdigest2"
    results = {}
    for part in output.split():
        alg, hexdigest = part.split(":", 1)
        digest_bytes = binascii.unhexlify(hexdigest)
        results[alg] = Digest(algorithm=alg, digest=digest_bytes)

    return results


def shard(
    hexdigest: str,
    width: int,
    depth: int,
) -> list[str]:
    """Shard hexdigest into path components."""
    parts = [hexdigest[i * width : (i + 1) * width] for i in range(depth)]
    return [p for p in parts if p] + [hexdigest]


def hexdigest_to_path(
    hexdigest: str,
    width: int,
    depth: int,
    root: Path | str | None = None,
) -> Path:
    """Convert hexdigest to sharded filesystem path."""
    parts = shard(hexdigest, width, depth)
    rel_path = Path(*parts)
    if root:
        return Path(root) / rel_path
    return rel_path


def read_blocks(
    filename: str | Path,
    block_size: int = 1048576,
) -> Iterable[bytes]:
    """
    Read file in blocks. Supports stdin via "-".
    Default block size: 1MB.
    """
    if filename == "-":
        f = sys.stdin.buffer
        close = False
    else:
        f = open(filename, "rb")
        close = True

    try:
        while chunk := f.read(block_size):
            yield chunk
    finally:
        if close:
            f.close()


def width_depth_combinations(
    max_width: int,
    max_depth: int,
) -> Iterable[tuple[int, int]]:
    """Generate valid (width, depth) combinations, excluding (0, *) and (*, 0)."""
    for w in range(1, max_width + 1):
        for d in range(1, max_depth + 1):
            yield (w, d)
