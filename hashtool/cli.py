#!/usr/bin/env python3
# -*- coding: utf8 -*-

from __future__ import annotations

import os
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click
from asserttool import ic
from click_auto_help import AHGroup
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tv
from eprint import eprint
from mptool import output
from unmp import unmp

from hashtool import get_available_algorithms
from hashtool import hash_str
from hashtool import rhash_file

# from threading import Thread
# from queue import Queue

# from collections.abc import Sequence
signal(SIGPIPE, SIG_DFL)


@click.group(no_args_is_help=True, cls=AHGroup)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    if not verbose:
        ic.disable()


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
    files: tuple[str, ...],
    disable_locking: bool,
    algorithms: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
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
        )

    for index, _path in enumerate(iterator):
        path = Path(os.fsdecode(_path)).expanduser()

        if verbose:
            ic(index, path)
        result = rhash_file(
            path=path,
            disable_locking=disable_locking,
            algorithms=algorithms,
        )

        for key, value in result.items():
            if len(algorithms) > 1:
                output(
                    {key: value},
                    reason=_path,
                    dict_output=dict_output,
                    tty=tty,
                )
            else:
                output(
                    value.digest,
                    reason=_path,
                    dict_output=dict_output,
                    tty=tty,
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
    algorithms: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
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
        _str_hash = hash_str(_str, algorithm=algorithm)
        output(
            _str_hash,
            reason=_str,
            dict_output=dict_output,
            tty=tty,
        )


@cli.command("empty-digests")
@click.option(
    "--algorithm",
    "algorithms",
    type=click.Choice(generate_hashlib_algorithm_set()),
    multiple=True,
)
@click_add_options(click_global_options)
@click.pass_context
def _empty_digests(
    ctx,
    algorithms: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    if not algorithms:
        algorithms = generate_hashlib_algorithm_set()

    for _alg in algorithms:
        _str_hash = hash_str("", algorithm=_alg)
        output(
            _str_hash,
            reason=_alg,
            dict_output=dict_output,
            tty=tty,
        )


@cli.command("empty-hexdigests")
@click.option(
    "--algorithm",
    "algorithms",
    type=click.Choice(generate_hashlib_algorithm_set()),
    multiple=True,
)
@click_add_options(click_global_options)
@click.pass_context
def _empty_hexdigests(
    ctx,
    algorithms: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    if not algorithms:
        algorithms = generate_hashlib_algorithm_set()

    for _alg in algorithms:
        _str_hash = hash_str("", algorithm=_alg)
        output(
            _str_hash.hex(),
            reason=_alg,
            dict_output=dict_output,
            tty=tty,
        )


# def hash_file_with_all_algorithms(
#    path: Path,
#    *,
#    verbose: bool = False,
# ):
#    if verbose:
#        ic(path)
#    path = Path(path).expanduser().resolve()
#    hashtool = MtHasher()
#    for data in read_blocks(path):
#        hashtool.update(data)
#    return hashtool
