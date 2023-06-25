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
from hashtool import hash_str
from unmp import unmp
from hashtool import generate_hashlib_algorithm_set
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
    verbose: bool | int | float = False,
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
    verbose: bool | int | float = False,
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
    algorithms: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool | int | float = False,
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
    verbose: bool | int | float = False,
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
    verbose: bool | int | float = False,
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
#    verbose: bool | int | float = False,
# ):
#    if verbose:
#        ic(path)
#    path = Path(path).expanduser().resolve()
#    hashtool = MtHasher()
#    for data in read_blocks(path):
#        hashtool.update(data)
#    return hashtool
