#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp


version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum-DASH requires Python version >= 2.7.0...")

requirements = []
# Read requirements.txt and strip newlines from it.
with open('requirements.txt') as f:
    requirements = [i.replace('\n', '') for i in f.readlines()]


data_files = []
if platform.system() in [ 'Linux', 'FreeBSD', 'DragonFly']:
    usr_share = os.path.join(sys.prefix, "share")
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum_dash.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum_dash.png'])
    ]

setup(
    name="Electrum-DASH",
    version=version.ELECTRUM_VERSION,
    install_requires=requirements,
    dependency_links=[
        'git+https://github.com/mazaclub/x11_hash@1.4#egg=x11_hash-1.4',
        'git+https://github.com/keepkey/python-keepkey@v0.7.2#egg=keepkey',
        'git+https://github.com/LedgerHQ/btchip-python.git@v0.1.17#egg=btchip',
    ],
    package_dir={
        'electrum_dash': 'lib',
        'electrum_dash_gui': 'gui',
        'electrum_dash_plugins': 'plugins',
    },
    packages=['electrum_dash','electrum_dash_gui','electrum_dash_gui.qt','electrum_dash_plugins'],
    package_data={
        'electrum_dash': [
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ],
        'electrum_dash_gui': [
            "qt/themes/cleanlook/name.cfg",
            "qt/themes/cleanlook/style.css",
            "qt/themes/sahara/name.cfg",
            "qt/themes/sahara/style.css",
            "qt/themes/dark/name.cfg",
            "qt/themes/dark/style.css",
        ]
    },
    scripts=['electrum-dash'],
    data_files=data_files,
    description="Lightweight Dashpay Wallet",
    author="mazaclub",
    license="GNU GPLv3",
    url="https://electrum.org",
    long_description="""Lightweight Dashpay Wallet"""
)
