#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=useless-suppression             # [I0021]
# pylint: disable=missing-docstring               # [C0111] docstrings are always outdated and wrong
# pylint: disable=fixme                           # [W0511] todo is encouraged
# pylint: disable=line-too-long                   # [C0301]
# pylint: disable=too-many-instance-attributes    # [R0902]
# pylint: disable=too-many-lines                  # [C0302] too many lines in module
# pylint: disable=invalid-name                    # [C0103] single letter var names, name too descriptive
# pylint: disable=too-many-return-statements      # [R0911]
# pylint: disable=too-many-branches               # [R0912]
# pylint: disable=too-many-statements             # [R0915]
# pylint: disable=too-many-arguments              # [R0913]
# pylint: disable=too-many-nested-blocks          # [R1702]
# pylint: disable=too-many-locals                 # [R0914]
# pylint: disable=too-few-public-methods          # [R0903]
# pylint: disable=no-member                       # [E1101] no member for base
# pylint: disable=attribute-defined-outside-init  # [W0201]
# pylint: disable=too-many-boolean-expressions    # [R0916] in if statement

from __future__ import annotations

import binascii
import hashlib
import os
import sys
from functools import lru_cache
from itertools import product
from math import inf
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal
from tempfile import _TemporaryFileWrapper
from typing import Iterable

import attr
import sh
from advisory_lock import AdvisoryLock
from asserttool import ic
from asserttool import maxone
from globalverbose import gvd
from retry_on_exception import retry_on_exception
from run_command import run_command

# from threading import Thread
# from queue import Queue

# from collections.abc import Sequence
signal(SIGPIPE, SIG_DFL)


class IncorrectHashError(ValueError):
    pass


class Digest:
    def __init__(
        self,
        algorithm: str,
        digest: None | bytes = None,
        preimage: None | bytes = None,
        verbose: bool = False,
    ):
        self.algorithm = algorithm
        # @singledispatch would be nice here, could pass bytes or str and not need to unhexlify
        maxone([digest, preimage])
        # one([digest, preimage])  fails on [None, b'']
        if digest is None:
            assert isinstance(preimage, bytes)
        if digest:
            assert isinstance(digest, bytes)
        if preimage is not None:
            assert isinstance(preimage, bytes)

        if preimage is not None:
            assert digest is None
            digest = getattr(hashlib, self.algorithm)(preimage).digest()

        self.digest = digest
        self.hexdigest = digest.hex()
        ic(self.hexdigest)

        # try:
        #    int(hexdigest, 16)
        # except ValueError:
        #    raise ValueError('Invalid ID: "{0}" is not hex'.format(hexdigest))
        # self.digest = binascii.unhexlify(self.hexdigest)
        self.digestlen = hashlib.new(self.algorithm).digest_size
        self.hexdigestlen = self.digestlen * 2
        if len(self.digest) != self.digestlen:
            msg = "hexdigest {} is not {} bytes long, as required by {}".format(
                self.hexdigest, self.hexdigestlen, self.algorithm
            )
            raise ValueError(msg)
            # raise ValueError('Invalid ID: "{}" is not {} digits long (len() is {})'.format(hexdigest, self.hexdigestlen,  len(hexdigest)))

    def __str__(self):
        return "<uhashfs.Digest " + self.hexdigest + ">"

    def __repr__(self):
        return str(self)

    def __len__(self):
        return len(self.digest)

    def __eq__(self, other):
        if self.digest == other.digest:
            return True
        return False


def md5_hash_file(
    path,
    *,
    block_size=256 * 128 * 2,
):
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            md5.update(chunk)
    return md5.hexdigest()


# todo kcl.iterops breakout
def compact(items):
    return [item for item in items if item]


def emptyhash(alg):
    emptydigest = getattr(hashlib, alg)(b"").digest()
    emptyhexdigest = emptydigest.hex()
    return emptyhexdigest


def hash_str(
    string: str,
    algorithm: str = "sha3_256",
):
    _digest = getattr(hashlib, algorithm)(string.encode("utf8"))
    # ic(algorithm, _digest)
    _digest = _digest.digest()
    # hexdigest = digest.hex()
    return _digest


def hexdigest_str_path_relative(
    *,
    hexdigest: str,
    width: int,
    depth: int,
) -> Path:
    path_elements = shard(
        hexdigest,
        width=width,
        depth=depth,
    )
    rel_path = Path(os.path.join(*path_elements))
    return rel_path


def hexdigest_str_path(
    *,
    root: Path,
    hexdigest: str,
    width: int,
    depth: int,
) -> Path:
    # root = Path(root).expanduser().resolve() # breaks uhashfs aliases
    root = Path(root)
    rel_path = hexdigest_str_path_relative(
        hexdigest=hexdigest,
        width=width,
        depth=depth,
    )
    path = root / rel_path
    return path


def shard(hexdigest, width, depth):
    return compact(
        [hexdigest[i * width : width * (i + 1)] for i in range(depth)] + [hexdigest]
    )


def generate_hashlib_algorithm_set():
    return [
        "sha1",
        "ripemd160",
        "sha512_256",
        "md5",
        "sha3_384",
        "shake_256",
        "mdc2",
        "sm3",
        "sha256",
        "whirlpool",
        "sha512",
        "sha224",
        "blake2s",
        "sha3_224",
        "md4",
        "sha3_512",
        "md5-sha1",
        "blake2b",
        "shake_128",
        "sha512_224",
        "sha384",
        "sha3_256",
    ]


@lru_cache
def re_generate_hashlib_algorithm_set():
    alg_set = set()
    algs = list(hashlib.algorithms_available)
    ic(algs)
    for alg in algs:
        if alg in [
            "ripemd160",
            "sha512_224",
            "sm3",
            "whirlpool",
            "md5-sha1",
            "sha512_256",
            "md4",
            "mdc2",
        ]:
            continue
        if alg.startswith("shake_"):
            continue
        if alg.startswith("sha3"):
            alg = alg.replace("-", "_")
        alg_set.add(alg)
    return list(alg_set)


def hash_readable(
    *,
    handle,
    algorithm: str,
    tmp: None | _TemporaryFileWrapper,
) -> bytes:
    block_size = 256 * 128 * 2
    hashtool = hashlib.new(algorithm)
    for chunk in iter(lambda: handle.read(block_size), b""):
        hashtool.update(chunk)
        if tmp:
            tmp.write(chunk)
    if tmp:
        # hm, tmp.file.name is an int
        os.posix_fadvise(tmp.file.name, 0, 0, os.POSIX_FADV_DONTNEED)
        tmp.close()
    return hashtool.digest()


@retry_on_exception(exception=PermissionError)
def hash_file(
    path: Path,
    *,
    algorithm: str,
    tmp: None | Path = None,
) -> bytes:
    path = Path(path).expanduser()
    fd = os.open(path, os.O_RDONLY)
    fh = os.fdopen(fd, "rb")
    try:
        digest = hash_readable(
            handle=fh,
            algorithm=algorithm,
            tmp=tmp,
        )
    except Exception as e:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        fh.close()
        raise e
    finally:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        fh.close()
    return digest


def rhash_file_sh(
    path: Path,
    *,
    disable_locking: bool,
    algorithms: Iterable,
) -> dict:
    def convert_digest_dict_to_objects(
        *,
        digest_dict: dict,
    ):
        digest_results = {}
        for key, hexdigest in digest_dict.items():
            # ic(hexdigest)
            digest = binascii.unhexlify(hexdigest)
            digest = Digest(
                algorithm=key,
                digest=digest,
            )
            digest_results[key] = digest
        return digest_results

    ic(disable_locking, path)
    path = Path(path).expanduser().resolve()
    assert algorithms
    result_dict = {}
    format_string = []
    # command = ['rhash',]
    rhash_command = sh.Command("rhash")
    for algorithm in algorithms:
        if algorithm == "sha3_256":
            # command.append('--sha3-256')
            rhash_command = rhash_command.bake("--sha3-256")
            format_string.append("sha3_256:%{sha3-256}")
        elif algorithm == "sha256":
            # command.append('--sha256')
            rhash_command = rhash_command.bake("--sha256")
            format_string.append("sha256:%{sha-256}")
        elif algorithm == "sha1":
            # command.append('--sha1')
            rhash_command = rhash_command.bake("--sha1")
            format_string.append("sha1:%{sha1}")
        else:
            raise NotImplementedError(algorithm)

    format_string = " ".join(format_string)
    format_string = f"--printf={format_string}"
    # command.append(format_string)
    rhash_command = rhash_command.bake(format_string)
    # command.append(path.as_posix())
    rhash_command = rhash_command.bake(path.as_posix())

    # ic(rhash_command)

    rhash_command_result = None
    if disable_locking:
        # try:
        rhash_command_result = rhash_command()
        # except sh.SignalException_SIGALRM:
        #    ic("sh.rhash got sh.SignalException_SIGALRM")
        #    assert rhash_command_result
        # ic(rhash_command_result)
    else:
        # ic(path)
        with AdvisoryLock(
            path=path,
            file_exists=True,
            open_read=True,
            # open_write=True,  #lockf needs R/W
            open_write=False,  # lockf needs R/W
            flock=True,
        ) as fl:
            rhash_command_result = rhash_command()
            # ic(rhash_command_result)

    assert rhash_command_result
    # ic(result)
    # ic(rhash_command_result)
    results = rhash_command_result.split(" ")
    for result in results:
        # ic(result)
        alg, hexdigest = result.split(":")
        result_dict[alg] = hexdigest

    if gvd:
        _path = path.as_posix()
        ic(_path, result_dict)
        del _path

    # ic(result_dict)
    digest_results = convert_digest_dict_to_objects(
        digest_dict=result_dict,
    )
    return digest_results


def rhash_file(
    path: Path,
    *,
    disable_locking: bool,
    algorithms: Iterable,
) -> dict:
    def convert_digest_dict_to_objects(
        *,
        digest_dict: dict,
    ):
        digest_results = {}
        for key, hexdigest in digest_dict.items():
            digest = binascii.unhexlify(hexdigest)
            digest = Digest(
                algorithm=key,
                digest=digest,
            )
            digest_results[key] = digest
        return digest_results

    if gvd:
        ic(disable_locking, path)
    path = Path(path).expanduser().resolve()
    assert algorithms
    result_dict = {}
    format_string = []
    command = [
        "rhash",
    ]
    for algorithm in algorithms:
        if algorithm == "sha3_256":
            command.append("--sha3-256")
            format_string.append("sha3_256:%{sha3-256}")
        elif algorithm == "sha256":
            command.append("--sha256")
            format_string.append("sha256:%{sha-256}")
        elif algorithm == "sha1":
            command.append("--sha1")
            format_string.append("sha1:%{sha1}")
        else:
            raise NotImplementedError(algorithm)

    format_string = " ".join(format_string)
    format_string = f"--printf='{format_string}'"
    command.append(format_string)
    command.append(f"'{path.as_posix()}'")
    rhash_command = " ".join(command)

    # epprint(f"{rhash_command=}")
    rhash_command_result = None
    if disable_locking:
        rhash_command_result = run_command(rhash_command, verbose=True)
    else:
        with AdvisoryLock(
            path=path,
            file_exists=True,
            open_read=True,
            # open_write=True,  #lockf needs R/W
            open_write=False,  # lockf needs R/W
            flock=True,
        ) as fl:
            rhash_command_result = run_command(rhash_command, verbose=True)

    # assert result
    assert rhash_command_result
    # ic(result)
    # ic(rhash_command_result)
    results = rhash_command_result.decode("utf8").split(" ")
    for result in results:
        # ic(result)
        alg, hexdigest = result.split(":")
        result_dict[alg] = hexdigest

    if gvd:
        _path = path.as_posix()
        ic(_path, result_dict)
        del _path

    # ic(result_dict)
    digest_results = convert_digest_dict_to_objects(
        digest_dict=result_dict,
    )
    return digest_results


@attr.s(auto_attribs=True)
class WDgen:
    width: int
    depth: int

    def __attrs_post_init__(self):
        self.gen = product(range(self.width), range(self.depth))

    def go(self):
        for w, d in self.gen:
            if w == 0:
                continue
            if d == 0:
                continue
            else:
                yield (w, d)


def sha1_hash_file(
    path,
    *,
    block_size=256 * 128 * 2,
    binary=False,
):
    sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            sha1.update(chunk)
    if binary:
        return sha1.digest()
    return sha1.hexdigest()


def sha3_256_hash_file(
    path: Path,
    block_size: int = 256 * 128 * 2,
) -> bytes:
    ic(path)
    sha3 = hashlib.sha3_256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            sha3.update(chunk)
    return sha3.digest()


# def get_openssl_hash_algs_real():
#    blacklist = set(["SHA", "MD4", "ecdsa-with-SHA1", "DSA", "DSA-SHA", "MDC2"])
#    results = []
#    command = " ".join(["openssl", "list-message-digest-algorithms"])
#    p = subprocess.Popen(
#        command,
#        shell=True,
#        stdout=subprocess.PIPE,
#        stderr=subprocess.STDOUT,
#    )
#    for line in p.stdout.readlines():
#        if b"=>" not in line:
#            line = line.strip()
#            #           line = line.lower()
#            line = line[:]
#            line = line.decode("ascii")
#            results.append(line)
#    return set(results) - blacklist


# def get_openssl_hash_algs():
#    return set(
#        [
#            "SHA1",
#            "MD5",
#            "RIPEMD160",
#            "SHA256",
#            "SHA384",
#            "SHA512",
#            "whirlpool",
#            "SHA224",
#        ]
#    )


def read_blocks(filename):
    if filename == "-":
        f = sys.stdin
        # Python 3 compat: read binary instead of unicode
        if hasattr(f, "buffer"):
            f = f.buffer
    else:
        f = open(filename, "rb")
    try:
        megabyte = 2**20
        while True:
            data = f.read(megabyte)
            if not data:
                break
            yield data
    finally:
        f.close()
