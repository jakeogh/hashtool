# -*- coding: utf-8 -*-


from setuptools import find_packages
from setuptools import setup

import fastentrypoints

dependencies = [
    "advisory-lock @ git+https://git@github.com/jakeogh/advisory_lock",
    "run-command @ git+https://git@github.com/jakeogh/run-command",
    "retry-on-exception @ git+https://git@github.com/jakeogh/retry_on_exception",
    "click-auto-help @ git+https://git@github.com/jakeogh/click-auto-help",
    "unmp @ git+https://git@github.com/jakeogh/unmp",
    "mpp @ git+https://git@github.com/jakeogh/mpp",
    "psutil",
    "attrs",
    "sh",
]

config = {
    "version": "0.1",
    "name": "hashtool",
    "url": "https://github.com/jakeogh/hashtool",
    "license": "ISC",
    "author": "Justin Keogh",
    "author_email": "github.com@v6y.net",
    "description": "common hash functions",
    "long_description": __doc__,
    "packages": find_packages(exclude=["tests"]),
    "package_data": {"hashtool": ["py.typed"]},
    "include_package_data": True,
    "zip_safe": False,
    "platforms": "any",
    "install_requires": dependencies,
    "entry_points": {
        "console_scripts": [
            "hashtool=hashtool.cli:cli",
        ],
    },
}

setup(**config)
