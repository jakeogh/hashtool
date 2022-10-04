# -*- coding: utf-8 -*-

import sys

from setuptools import find_packages
from setuptools import setup

import fastentrypoints

if not sys.version_info[0] == 3:
    sys.exit("Python 3 is required. Use: 'python3 setup.py install'")

dependencies = [
    "advisory-lock @ git+https://git@github.com/jakeogh/advisory_lock",
    "retry-on-exception @ git+https://git@github.com/jakeogh/retry_on_exception",
]

config = {
    "version": "0.1",
    "name": "hashtool",
    "url": "https://github.com/jakeogh/hashtool",
    "license": "ISC",
    "author": "Justin Keogh",
    "author_email": "github.com@v6y.net",
    "description": "Short explination of what it does _here_",
    "long_description": __doc__,
    "packages": find_packages(exclude=["tests"]),
    "package_data": {"hashtool": ["py.typed"]},
    "include_package_data": True,
    "zip_safe": False,
    "platforms": "any",
    "install_requires": dependencies,
    "entry_points": {
        "console_scripts": [
            "hashtool=hashtool.hashtool:cli",
        ],
    },
}

setup(**config)
