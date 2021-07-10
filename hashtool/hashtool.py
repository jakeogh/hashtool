#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=C0111  # docstrings are always outdated and wrong
# pylint: disable=W0511  # todo is encouraged
# pylint: disable=C0301  # line too long
# pylint: disable=R0902  # too many instance attributes
# pylint: disable=C0302  # too many lines in module
# pylint: disable=C0103  # single letter var names, func name too descriptive
# pylint: disable=R0911  # too many return statements
# pylint: disable=R0912  # too many branches
# pylint: disable=R0915  # too many statements
# pylint: disable=R0913  # too many arguments
# pylint: disable=R1702  # too many nested blocks
# pylint: disable=R0914  # too many local variables
# pylint: disable=R0903  # too few public methods
# pylint: disable=E1101  # no member for base
# pylint: disable=W0201  # attribute defined outside __init__
# pylint: disable=R0916  # Too many boolean expressions in if statement


import hashlib
import os
import subprocess
import sys
import tempfile
from itertools import product
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import ByteString
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence

import attr
import click
from asserttool import eprint
from asserttool import ic
from asserttool import nevd
from asserttool import verify
from enumerate_input import enumerate_input
from getdents import paths
from requests.models import Response
from retry_on_exception import retry_on_exception
from run_command import run_command

## todo kcl.assertops breakout
#def verify(thing):
#    if not thing:
#        raise ValueError(thing)


# todo kcl.iterops breakout
def compact(items):
    return [item for item in items if item]


def emptyhash(alg):
    emptydigest = getattr(hashlib, alg)(b'').digest()
    emptyhexdigest = emptydigest.hex()
    return emptyhexdigest


def hexdigest_str_path_relative(hexdigest: str,
                                width: int,
                                depth: int,
                                ) -> Path:

    path_elements = shard(hexdigest, width=width, depth=depth)
    rel_path = Path(os.path.join(*path_elements))
    return rel_path


def hexdigest_str_path(root: Path,
                       hexdigest: str,
                       width: int,
                       depth: int,
                       ) -> Path:

    root = Path(root).expanduser().resolve()
    rel_path = hexdigest_str_path_relative(hexdigest=hexdigest,
                                           width=width,
                                           depth=depth,)
    path = root / rel_path
    return path


def shard(hexdigest, width, depth):
    return compact([hexdigest[i * width:width * (i + 1)]
                    for i in range(depth)] + [hexdigest])


def generate_hashlib_algorithm_set():
    alg_set = set()
    algs = list(hashlib.algorithms_available)
    for alg in algs:
        if alg.startswith('sha3'):
            alg = alg.replace('-', '_')
        alg_set.add(alg)
    return list(alg_set)


def hash_readable(handle,
                  algorithm: str,
                  tmp,
                  ) -> bytes:
    block_size = 256 * 128 * 2
    hashtool = hashlib.new(algorithm)
    for chunk in iter(lambda: handle.read(block_size), b''):
        hashtool.update(chunk)
        if tmp:
            tmp.write(chunk)
    if tmp:
        os.posix_fadvise(tmp.file.name, 0, 0, os.POSIX_FADV_DONTNEED)
        tmp.close()
    return hashtool.digest()


@retry_on_exception(exception=PermissionError)
def hash_file(path: Path,
              *,
              algorithm: str,
              tmp,
              verbose: bool,
              debug: bool,
              ) -> bytes:
    path = Path(path).expanduser()
    fd = os.open(path, os.O_RDONLY)
    fh = os.fdopen(fd, 'rb')
    try:
        digest = hash_readable(fh, algorithm, tmp)
    except Exception as e:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        fh.close()
        raise e
    finally:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        fh.close()
    return digest


def hash_file_with_all_algorithms(path: Path,
                                  *,
                                  verbose: bool,
                                  debug: bool,
                                  ):
    if verbose:
        ic(path)
    path = Path(path).expanduser().resolve()
    hashtool = MtHasher()
    for data in read_blocks(path):
        hashtool.update(data)
    return hashtool


def hash_file_handle(handle,
                     *,
                     algorithm: str,
                     tmp,
                     verbose: bool,
                     debug: bool,
                     ):
    assert False
    pos = handle.tell()
    digest = hash_readable(handle, algorithm, tmp)
    handle.seek(pos)
    return digest


def rhash_file(path: Path,
               *,
               algorithms: Iterable,
               verbose: bool,
               debug: bool,
               ) -> dict:
    path = Path(path).expanduser().resolve()
    assert algorithms
    result_dict = {}
    format_string = []
    command = ['rhash',]
    for algorithm in algorithms:
        if algorithm == 'sha3_256':
            command.append('--sha3-256')
            format_string.append('sha3_256:%{sha3-256}')
        elif algorithm == 'sha256':
            command.append('--sha256')
            format_string.append('sha256:%{sha-256}')
        elif algorithm == 'sha1':
            command.append('--sha1')
            format_string.append('sha1:%{sha1}')
        else:
            raise NotImplementedError(algorithm)

    format_string = ' '.join(format_string)
    format_string = '--printf="{}"'.format(format_string)
    command.append(format_string)
    command.append(path.as_posix())

    #ic(command)

    result = run_command(command, shell=True).decode('utf8')
    #ic(result)
    results = result.split(' ')
    for result in results:
        #ic(result)
        alg, hexdigest = result.split(':')
        result_dict[alg] = hexdigest

    if debug:
        _path = path.as_posix()
        ic(_path, result_dict)
        del _path

    return result_dict


@attr.s(auto_attribs=True)
class WDgen():
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


def generate_hash(data, *,
                  verbose: bool,
                  debug: bool,
                  ):
    if not data:
        raise ValueError
    sha1 = hashlib.sha1()
    chunk_size = 128 * sha1.block_size  # 8MB
    return_dict = {}
    if isinstance(data, tempfile._TemporaryFileWrapper):
        filename = data.name
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                sha1.update(chunk)
        return_dict['hash'] = sha1.hexdigest()
        return return_dict
    elif isinstance(data, Response):
        # todo make temp_folder configurable, make sure it exists
        with tempfile.NamedTemporaryFile(mode='wb',
                                         suffix='.tmp',
                                         prefix='tmp-',
                                         dir='/var/tmp/iridb',
                                         delete=False,) as temp_file:
            if verbose:
                #import IPython; IPython.embed()
                ic(data.url)
            try:
                data_size_from_headers = int(data.headers['Content-Length'])
                #ic(data_size_from_headers)
            except KeyError:
                data_size_from_headers = False
            for chunk in data.iter_content(chunk_size):
                sha1.update(chunk)
                temp_file.write(chunk)
                current_file_size = int(os.path.getsize(temp_file.name))
                if data_size_from_headers:
                    eprint(temp_file.name,
                           str(int((current_file_size / data_size_from_headers) * 100)) + '%',
                           current_file_size,
                           data.url,
                           end='\r',
                           flush=True,)
                else:
                    eprint(temp_file.name,
                           current_file_size,
                           data.url,
                           end='\r',
                           flush=True,)

        current_file_size = int(os.path.getsize(temp_file.name))
        # update final size
        if data_size_from_headers:
            eprint(temp_file.name,
                   str(int((current_file_size / data_size_from_headers) * 100)) + '%',
                   current_file_size,
                   data.url,
                   end='\r',
                   flush=True,)
        else:
            eprint(temp_file.name,
                   current_file_size,
                   data.url,
                   end='\r',
                   flush=True,)

        if verbose:
            eprint('\n', end='')
        #eprint('finished writing temp_file:', temp_file.name)
        if os.path.getsize(temp_file.name) == 0:
            ic('content is zero bytes, raising FileNotFoundError')  # this happens
            raise FileNotFoundError
        return_dict['hash'] = sha1.hexdigest()
        assert return_dict['hash']
        return_dict['temp_file'] = temp_file
        return return_dict
    else:
        try:
            if len(data) == 0:
                # empty_hash = hashlib.sha1(data).hexdigest()
                ic('Error: you are attempting to hash a empty string.')
                raise FileNotFoundError
        except TypeError:
            raise FileNotFoundError

        if isinstance(data, str):
            return_dict['hash'] = hashlib.sha1(data.encode('utf-8')).hexdigest()
        else:
            return_dict['hash'] = hashlib.sha1(data).hexdigest()
        return return_dict


def sha1_hash_file(path, *,
                   verbose: bool,
                   debug: bool,
                   block_size=256 * 128 * 2,
                   binary=False,
                   ):
    sha1 = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            sha1.update(chunk)
    if binary:
        return sha1.digest()
    return sha1.hexdigest()


def sha3_256_hash_file(path,
                       block_size=256 * 128 * 2,
                       binary=False,
                       ):
    sha3 = hashlib.sha3_256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            sha3.update(chunk)
    if binary:
        return sha3.digest()
    return sha3.hexdigest()


def get_openssl_hash_algs_real():
    blacklist = set(['SHA', 'MD4', 'ecdsa-with-SHA1', 'DSA', 'DSA-SHA', 'MDC2'])
    results = []
    command = ' '.join(['openssl', 'list-message-digest-algorithms'])
    p = subprocess.Popen(command,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,)
    for line in p.stdout.readlines():
        if b'=>' not in line:
            line = line.strip()
#           line = line.lower()
            line = line[:]
            line = line.decode('ascii')
            results.append(line)
    return set(results) - blacklist


def get_openssl_hash_algs():
    return set(['SHA1', 'MD5', 'RIPEMD160', 'SHA256', 'SHA384', 'SHA512', 'whirlpool', 'SHA224'])


def read_blocks(filename):
    if filename == '-':
        f = sys.stdin
        # Python 3 compat: read binary instead of unicode
        if hasattr(f, 'buffer'):
            f = f.buffer
    else:
        f = open(filename, 'rb')
    try:
        megabyte = 2 ** 20
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
    '''Calculate multiple hash digests for a piece of data.'''
    def __init__(self, algos):
        self.algos = algos
        self._hashes = {}
        for algo in self.algos:
            self._hashes[algo] = getattr(hashlib, 'new')(algo)

    def update(self, data):
        for h in self._hashes:
            eprint(h)
            h.update(data)

    def hexdigests(self):
        '''Yields the algorithm and the calculated hex digest.'''
        for algo in self.algos:
            digest = self._hashes[algo].hexdigest()
            yield algo.lower(), digest

    def digests(self):
        '''Yields the algorithm and the calculated bytes digest.'''
        for algo in self.algos:
            digest = self._hashes[algo].digest()
            yield algo.lower(), digest


class MtHasher(Hasher):
    # Queue size. Memory usage is this times block size (1M)
    QUEUE_SIZE = 10

    def __init__(self):
        algos = get_openssl_hash_algs()
        #eprint("algos:", algos)
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
        '''Wait until all calculations are done and yield hexdigests in the meantime.'''
        for algo in self.algos:
            q = self._queues[algo]
            q.put(b'')  # Terminate
            self._threads[algo].join()
            assert q.empty()
        return super(MtHasher, self).hexdigests()

    def digests(self):
        '''Wait until all calculations are done and yield digests in the meantime.'''
        for algo in self.algos:
            q = self._queues[algo]
            q.put(b'')  # Terminate
            self._threads[algo].join()
            assert q.empty()
        return super(MtHasher, self).digests()


def hash_bytes(byte_string):
    if isinstance(byte_string, str):
        byte_string = byte_string.encode('UTF-8')
    hashtool = MtHasher()
    '''encode unicode to UTF-8, read bytes and update the hash states. '''
    hashtool.update(byte_string)
    return hashtool


def bytes_dict_file(path, verbose: bool, debug: bool,):
    bytes_dict = {}
    hashtool = hash_file_with_all_algorithms(path=path, verbose=verbose, debug=debug,)
    for algo, digest in hashtool.digests():
        bytes_dict[algo] = digest
    return bytes_dict


def bytes_dict_bytes(byte_string):
    bytes_dict = {}
    hashtool = hash_bytes(byte_string)
    for algo, digest in hashtool.digests():
        bytes_dict[algo] = digest
    return bytes_dict


def hex_dict_file(path, verbose: bool, debug: bool,):
    bytes_dict = {}
    hashtool = hash_file_with_all_algorithms(path=path, verbose=verbose, debug=debug,)
    for algo, digest in hashtool.hexdigests():
        bytes_dict[algo] = digest
    return bytes_dict


def detect_hash_tree_width_and_depth(*,
                                     root,
                                     alg: str,
                                     verbose: bool,
                                     debug: bool,
                                     max_width: int = 5,
                                     max_depth: int = 5,
                                     ):
    verify(isinstance(root, Path))
    #empty_hexdigest = emptyhash(alg)
    #empty_hexdigest_length = len(empty_hexdigest)
    width = 0
    depth = 0
    verify(alg == root.name)

    for path in paths(path=root,
                      names_only=False,
                      return_dirs=False,
                      return_files=True,
                      return_symlinks=True,
                      verbose=verbose,
                      debug=debug,
                      ):
        path = path.pathlib
        #ic(path)
        relative_path = path.relative_to(root)
        #ic(relative_path)
        relative_path_parts = relative_path.parts
        width = len(relative_path_parts[0])
        for depth, part in enumerate(relative_path_parts):
            if len(part) != width:
                if verbose:
                    ic(width)
                    ic(depth)
                return width, depth

    message = "Unable to detect width/depth."
    raise ValueError(message)


@click.command()
@click.argument("files", type=str, nargs=-1)
@click.option('--algorithm', 'algorithms',
              type=click.Choice(generate_hashlib_algorithm_set()),
              default=['sha3_256'],
              multiple=True,)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.pass_context
def cli(ctx,
        files: tuple[str],
        algorithms: tuple[str],
        verbose: bool,
        debug: bool,
        ):

    null, end, verbose, debug = nevd(ctx=ctx,
                                     printn=False,
                                     ipython=False,
                                     verbose=verbose,
                                     debug=debug,)

    iterator = files

    for index, path in enumerate_input(iterator=iterator,
                                       null=null,
                                       progress=False,
                                       skip=None,
                                       head=None,
                                       tail=None,
                                       debug=debug,
                                       verbose=verbose,):
        path = Path(path).expanduser()

        if verbose:
            ic(index, path)
        result = hash_file_with_all_algorithms(path=path,
                                               verbose=verbose,
                                               debug=debug,)
        ic(dir(result))
        #print(result())