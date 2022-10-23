#!/usr/bin/env python3
# -*- coding: utf8 -*-

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
import subprocess
import sys
import tempfile
from itertools import product
from math import inf
from pathlib import Path
from queue import Queue
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal
from tempfile import _TemporaryFileWrapper
from threading import Thread
from typing import Iterable

import attr
import click
import sh
from advisory_lock import AdvisoryLock
from asserttool import ic
from asserttool import increment_debug
from asserttool import maxone
from asserttool import one
from click_auto_help import AHGroup
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tv
from eprint import eprint
# from getdents import paths
from mptool import output
from requests.models import Response
from retry_on_exception import retry_on_exception
from unmp import unmp

# from collections.abc import Sequence
signal(SIGPIPE, SIG_DFL)


class Digest:
    def __init__(
        self,
        algorithm: str,
        verbose: bool | int | float,
        digest: None | bytes = None,
        preimage: None | bytes = None,
    ):

        self.algorithm = algorithm
        # @singledispatch would be nice here, could pass bytes or str and not need to unhexlify
        maxone([digest, preimage])
        one([digest, preimage])
        if digest:
            assert isinstance(digest, bytes)
        if preimage:
            assert isinstance(preimage, bytes)

        if preimage:
            assert digest is None
            digest = getattr(hashlib, self.algorithm)(preimage).digest()

        self.digest = digest
        self.hexdigest = digest.hex()
        if verbose == inf:
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
    verbose: bool | int | float,
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


def hash_str(string: str, verbose: bool | int | float, algorithm: str = "sha3_256"):
    digest = getattr(hashlib, algorithm)(string.encode("utf8")).digest()
    # hexdigest = digest.hex()
    return digest


def hexdigest_str_path_relative(
    *,
    hexdigest: str,
    width: int,
    depth: int,
    verbose: bool | int | float,
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
    verbose: bool | int | float,
) -> Path:

    root = Path(root).expanduser().resolve()
    rel_path = hexdigest_str_path_relative(
        hexdigest=hexdigest,
        width=width,
        depth=depth,
        verbose=verbose,
    )
    path = root / rel_path
    return path


def shard(hexdigest, width, depth):
    return compact(
        [hexdigest[i * width : width * (i + 1)] for i in range(depth)] + [hexdigest]
    )


def generate_hashlib_algorithm_set():
    alg_set = set()
    algs = list(hashlib.algorithms_available)
    for alg in algs:
        if alg.startswith("sha3"):
            alg = alg.replace("-", "_")
        alg_set.add(alg)
    return list(alg_set)


def hash_readable(
    *,
    handle,
    algorithm: str,
    tmp: None | _TemporaryFileWrapper,
    verbose: bool | int | float,
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
    verbose: bool | int | float,
) -> bytes:
    path = Path(path).expanduser()
    fd = os.open(path, os.O_RDONLY)
    fh = os.fdopen(fd, "rb")
    try:
        digest = hash_readable(
            handle=fh,
            algorithm=algorithm,
            tmp=tmp,
            verbose=verbose,
        )
    except Exception as e:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        fh.close()
        raise e
    finally:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        fh.close()
    return digest


def hash_file_with_all_algorithms(
    path: Path,
    *,
    verbose: bool | int | float,
):
    if verbose:
        ic(path)
    path = Path(path).expanduser().resolve()
    hashtool = MtHasher()
    for data in read_blocks(path):
        hashtool.update(data)
    return hashtool


@increment_debug
def rhash_file(
    path: Path,
    *,
    disable_locking: bool,
    algorithms: Iterable,
    verbose: bool | int | float,
) -> dict:
    def convert_digest_dict_to_objects(
        *,
        digest_dict: dict,
        verbose: bool | int | float,
    ):

        digest_results = {}
        for key, hexdigest in digest_dict.items():
            # ic(hexdigest)
            digest = binascii.unhexlify(hexdigest)
            digest = Digest(
                algorithm=key,
                digest=digest,
                verbose=verbose,
            )
            digest_results[key] = digest
        return digest_results

    if verbose == inf:
        ic(disable_locking, path)
    # assert verbose
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
        try:
            rhash_command_result = rhash_command()
        except sh.SignalException_SIGALRM:
            ic("sh.rhash got sh.SignalException_SIGALRM")
            assert rhash_command_result
        # ic(rhash_command_result)
        # result = run_command(command, shell=True).decode('utf8')
    else:
        # if verbose:
        #    ic(path)
        # ic(verbose)
        with AdvisoryLock(
            path=path,
            file_exists=True,
            open_read=True,
            # open_write=True,  #lockf needs R/W
            open_write=False,  # lockf needs R/W
            flock=True,
            verbose=verbose,
        ) as fl:

            rhash_command_result = rhash_command()
            # ic(rhash_command_result)
            # result = run_command(command, shell=True).decode('utf8')

    # assert result
    assert rhash_command_result
    # ic(result)
    # ic(rhash_command_result)
    results = rhash_command_result.split(" ")
    for result in results:
        # ic(result)
        alg, hexdigest = result.split(":")
        result_dict[alg] = hexdigest

    if verbose == inf:
        _path = path.as_posix()
        ic(_path, result_dict)
        del _path

    # ic(result_dict)
    digest_results = convert_digest_dict_to_objects(
        digest_dict=result_dict,
        verbose=verbose,
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


def generate_hash(
    data,
    *,
    verbose: bool | int | float,
):
    if not data:
        raise ValueError
    sha1 = hashlib.sha1()
    chunk_size = 128 * sha1.block_size  # 8MB
    return_dict = {}
    if isinstance(data, tempfile._TemporaryFileWrapper):
        filename = data.name
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha1.update(chunk)
        return_dict["hash"] = sha1.hexdigest()
        return return_dict
    elif isinstance(data, Response):
        # todo make temp_folder configurable, make sure it exists
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".tmp",
            prefix="tmp-",
            dir="/var/tmp/iridb",
            delete=False,
        ) as temp_file:
            if verbose:
                # import IPython; IPython.embed()
                ic(data.url)
            try:
                data_size_from_headers = int(data.headers["Content-Length"])
                # ic(data_size_from_headers)
            except KeyError:
                data_size_from_headers = False
            for chunk in data.iter_content(chunk_size):
                sha1.update(chunk)
                temp_file.write(chunk)
                current_file_size = int(os.path.getsize(temp_file.name))
                if data_size_from_headers:
                    eprint(
                        temp_file.name,
                        str(int((current_file_size / data_size_from_headers) * 100))
                        + "%",
                        current_file_size,
                        data.url,
                        end="\r",
                        flush=True,
                    )
                else:
                    eprint(
                        temp_file.name,
                        current_file_size,
                        data.url,
                        end="\r",
                        flush=True,
                    )

        current_file_size = int(os.path.getsize(temp_file.name))
        # update final size
        if data_size_from_headers:
            eprint(
                temp_file.name,
                str(int((current_file_size / data_size_from_headers) * 100)) + "%",
                current_file_size,
                data.url,
                end="\r",
                flush=True,
            )
        else:
            eprint(
                temp_file.name,
                current_file_size,
                data.url,
                end="\r",
                flush=True,
            )

        if verbose:
            eprint("\n", end="")
        # eprint('finished writing temp_file:', temp_file.name)
        if os.path.getsize(temp_file.name) == 0:
            ic("content is zero bytes, raising FileNotFoundError")  # this happens
            raise FileNotFoundError
        return_dict["hash"] = sha1.hexdigest()
        assert return_dict["hash"]
        return_dict["temp_file"] = temp_file
        return return_dict
    else:
        try:
            if len(data) == 0:
                # empty_hash = hashlib.sha1(data).hexdigest()
                ic("Error: you are attempting to hash a empty string.")
                raise FileNotFoundError
        except TypeError:
            raise FileNotFoundError

        if isinstance(data, str):
            return_dict["hash"] = hashlib.sha1(data.encode("utf-8")).hexdigest()
        else:
            return_dict["hash"] = hashlib.sha1(data).hexdigest()
        return return_dict


def sha1_hash_file(
    path,
    *,
    verbose: bool | int | float,
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
    verbose: bool | int | float,
    block_size: int = 256 * 128 * 2,
) -> bytes:
    if verbose:
        ic(path)
    sha3 = hashlib.sha3_256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            sha3.update(chunk)
    return sha3.digest()


def get_openssl_hash_algs_real():
    blacklist = set(["SHA", "MD4", "ecdsa-with-SHA1", "DSA", "DSA-SHA", "MDC2"])
    results = []
    command = " ".join(["openssl", "list-message-digest-algorithms"])
    p = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    for line in p.stdout.readlines():
        if b"=>" not in line:
            line = line.strip()
            #           line = line.lower()
            line = line[:]
            line = line.decode("ascii")
            results.append(line)
    return set(results) - blacklist


def get_openssl_hash_algs():
    return set(
        [
            "SHA1",
            "MD5",
            "RIPEMD160",
            "SHA256",
            "SHA384",
            "SHA512",
            "whirlpool",
            "SHA224",
        ]
    )


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


# Calculate (multiple) digest(s) for file(s)
# Author: Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>
# http://unix.stackexchange.com/questions/163747/simultaneously-calculate-multiple-digests-md5-sha256
# https://git.lekensteyn.nl/scripts/tree/digest.py


class Hasher(object):
    """Calculate multiple hash digests for a piece of data."""

    def __init__(self, algos):
        self.algos = algos
        self._hashes = {}
        for algo in self.algos:
            self._hashes[algo] = getattr(hashlib, "new")(algo)

    def update(self, data):
        for h in self._hashes:
            eprint(h)
            h.update(data)

    def hexdigests(self):
        """Yields the algorithm and the calculated hex digest."""
        for algo in self.algos:
            digest = self._hashes[algo].hexdigest()
            yield algo.lower(), digest

    def digests(self):
        """Yields the algorithm and the calculated bytes digest."""
        for algo in self.algos:
            digest = self._hashes[algo].digest()
            yield algo.lower(), digest


class MtHasher(Hasher):
    # Queue size. Memory usage is this times block size (1M)
    QUEUE_SIZE = 10

    def __init__(self):
        algos = get_openssl_hash_algs()
        assert False  # woah, every alg lol
        # eprint("algos:", algos)
        super(MtHasher, self).__init__(algos)
        self._queues = {}
        self._threads = {}
        for algo in algos:
            t = Thread(target=self._queue_updater, args=(algo,), name=algo)
            self._queues[algo] = Queue(MtHasher.QUEUE_SIZE)
            self._threads[algo] = t
            t.start()

    def _queue_updater(self, algo):
        q = self._queues[algo]
        h = self._hashes[algo]
        while True:
            data = q.get()
            # Treat an empty value as terminator
            if not data:
                break
            h.update(data)

    def update(self, data):
        if data:
            for q in self._queues.values():
                q.put(data)

    def hexdigests(self):
        """Wait until all calculations are done and yield hexdigests in the meantime."""
        for algo in self.algos:
            q = self._queues[algo]
            q.put(b"")  # Terminate
            self._threads[algo].join()
            assert q.empty()
        return super(MtHasher, self).hexdigests()

    def digests(self):
        """Wait until all calculations are done and yield digests in the meantime."""
        for algo in self.algos:
            q = self._queues[algo]
            q.put(b"")  # Terminate
            self._threads[algo].join()
            assert q.empty()
        return super(MtHasher, self).digests()


def hash_bytes(byte_string: bytes):
    if isinstance(byte_string, str):
        raise TypeError(type(byte_string))
        # byte_string = byte_string.encode("UTF-8")
    hashtool = MtHasher()
    hashtool.update(byte_string)
    return hashtool


def bytes_dict_file(
    path,
    verbose: bool | int | float,
):
    bytes_dict = {}
    hashtool = hash_file_with_all_algorithms(
        path=path,
        verbose=verbose,
    )
    for algo, digest in hashtool.digests():
        bytes_dict[algo] = digest
    return bytes_dict


def bytes_dict_bytes(byte_string):
    bytes_dict = {}
    hashtool = hash_bytes(byte_string)
    for algo, digest in hashtool.digests():
        bytes_dict[algo] = digest
    return bytes_dict


def hex_dict_file(
    path,
    verbose: bool | int | float,
):
    bytes_dict = {}
    hashtool = hash_file_with_all_algorithms(
        path=path,
        verbose=verbose,
    )
    for algo, digest in hashtool.hexdigests():
        bytes_dict[algo] = digest
    return bytes_dict


# def detect_hash_tree_width_and_depth(
#    *,
#    root: Path,
#    alg: str,
#    verbose: bool | int | float,
#    max_width: int = 5,
#    max_depth: int = 5,
# ):
#    assert isinstance(root, Path)
#    # empty_hexdigest = emptyhash(alg)
#    # empty_hexdigest_length = len(empty_hexdigest)
#    width = 0
#    depth = 0
#    assert alg == root.name
#
#    for path in paths(
#        path=root,
#        return_dirs=False,
#        return_files=True,
#        return_symlinks=True,
#        verbose=verbose,
#    ):
#        path = path.pathlib
#        # ic(path)
#        relative_path = path.relative_to(root)
#        # ic(relative_path)
#        relative_path_parts = relative_path.parts
#        width = len(relative_path_parts[0])
#        for depth, part in enumerate(relative_path_parts):
#            if len(part) != width:
#                if verbose:
#                    ic(width)
#                    ic(depth)
#                return width, depth
#
#    message = "Unable to detect width/depth."
#    raise ValueError(message)


@click.group(no_args_is_help=True, cls=AHGroup)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
) -> None:

    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )


@cli.command("files")
@click.argument("files", type=str, nargs=-1)
@click.option(
    "--algorithm",
    "algorithms",
    type=click.Choice(generate_hashlib_algorithm_set()),
    default=["sha3_256"],
    multiple=True,
)
@click.option("--disable-locking", is_flag=True)
@click_add_options(click_global_options)
@click.pass_context
def _files(
    ctx,
    files: tuple[str],
    disable_locking: bool,
    algorithms: tuple[str],
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
):

    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )
    if files:
        iterator = files
    else:
        iterator = unmp(
            valid_types=[
                bytes,
            ],
            verbose=verbose,
        )

    for index, _path in enumerate(iterator):
        path = Path(os.fsdecode(_path)).expanduser()

        if verbose:
            ic(index, path)
        result = rhash_file(
            path=path,
            disable_locking=disable_locking,
            algorithms=algorithms,
            verbose=verbose,
        )

        for key, value in result.items():
            if len(algorithms) > 1:
                output(
                    {key: value},
                    reason=_path,
                    dict_output=dict_output,
                    tty=tty,
                    verbose=verbose,
                )
            else:
                output(
                    value.digest,
                    reason=_path,
                    dict_output=dict_output,
                    tty=tty,
                    verbose=verbose,
                )


@cli.command("strings")
@click.option(
    "--algorithm",
    "algorithms",
    type=click.Choice(generate_hashlib_algorithm_set()),
    default=["sha3_256"],
    multiple=True,
)
@click_add_options(click_global_options)
@click.pass_context
def _strings(
    ctx,
    algorithms: tuple[str],
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
):

    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    iterator = unmp(
        valid_types=[
            bytes,
            str,
        ],
        verbose=verbose,
    )

    algorithm = algorithms[0]
    for index, _str in enumerate(iterator):
        _str_hash = hash_str(_str, algorithm=algorithm, verbose=verbose)
        output(
            _str_hash,
            reason=_str,
            dict_output=dict_output,
            tty=tty,
            verbose=verbose,
        )
