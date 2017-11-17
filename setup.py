"""setup.py file."""

import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements

__author__ = 'Benny Holmgren <benny@holmgren.id.au>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-mos",
    version="2.0.1",
    packages=find_packages(),
    author="Benny Holmgren, Brandon Ewing",
    author_email="benny@holmgren.id.au, brandon.ewing@warningg.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/napalm-mos",
    include_package_data=True,
    install_requires=reqs,
)
