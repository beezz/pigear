#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pigear
from distutils.core import setup


setup(
    name='pigear',
    version=pigear.__version__,
    description='Snort NIDS unix socket reader',
    author='Michal Kuffa',
    author_email='michal.kuffa@gmail.com',
    packages= [
        'pigear',
        'pigear.contrib',
    ],
    license='ISC',
    classifiers=(
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Topic :: System :: Networking :: Monitoring',
    ),
)
