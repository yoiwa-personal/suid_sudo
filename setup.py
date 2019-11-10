#!/usr/bin/python3
import setuptools
import os
with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
#    setup_requires=['setuptools_scm'],
#    use_scm_version=True,
    name="suid_sudo",
    version="0.1",
    author="Yutaka OIWA",
    author_email="yutaka@oiwa.jp",
    description="Library for emulating setuid by sudo",
    long_description=long_description,
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
