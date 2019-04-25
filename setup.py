"""setup.py file."""
from setuptools import setup, find_packages

__author__ = "Benny Holmgren <benny@holmgren.id.au>"

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

setup(
    name="napalm-mos",
    version="2.4.0",
    packages=find_packages(),
    author="Benny Holmgren, Brandon Ewing",
    author_email="benny@holmgren.id.au, brandon.ewing@warningg.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    url="https://github.com/napalm-automation-community/napalm-mos",
    include_package_data=True,
    install_requires=reqs,
)
