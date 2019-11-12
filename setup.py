#!/usr/bin/python3
import setuptools
import os

import suid_sudo

#with open("README.md", "r") as fh:
#    long_description = fh.read()
with open("VERSION", "r") as fh:
    version = fh.readline().strip()

setuptools.setup(
#    setup_requires=['setuptools_scm'],
#    use_scm_version=True,
    name="suid_sudo",
    version=version,
    author="Yutaka OIWA",
    author_email="yutaka@oiwa.jp",
    description="Library for emulating setuid by sudo",
    long_description=suid_sudo.__doc__,
    long_description_content_type="text/markdown",
    license="Apache License, Version 2.0",
    url="https://github.com/yoiwa_personal/suid_sudo/",
    py_modules=['suid_sudo'],
    data_files=[('doc', ['README.md', 'doc/APIs.md'])],
    classifiers=(
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Linux",
    ),
)
