#!/usr/bin/env python3

from setuptools import setup, find_packages
import sys, os

version = '0.1'

# License :: OSI Approved :: MIT License

setup(
    name='par2py',
    version=version,
    description="par2 Python Utilities",
    long_description=open('README.md').read(),
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
    ],
    keywords='par2',
    author='Arthur Moore',
    author_email='arthur.moore.git@cd-net.net',
    url='http://github.com/EmperorArthur/par2py',
    license='MIT',
    packages=['par2'],
    scripts=[],
    include_package_data=True,
    zip_safe=True,
    test_suite="tests",
    install_requires=[
        # -*- Extra requirements: -*-
    ],
    entry_points="""
    # -*- Entry points: -*-
    """,
)
