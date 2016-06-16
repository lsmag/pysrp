#!/usr/bin/env python

import os
import sys
from setuptools import Extension
from distutils.core      import setup
from setuptools.command.test import test as TestCommand


long_description = '''

This package provides an implementation of the Secure Remote Password
protocol (SRP). SRP is a cryptographically strong authentication
protocol for password-based, mutual authentication over an insecure
network connection.

Unlike other common challenge-response autentication protocols, such
as Kereros and SSL, SRP does not rely on an external infrastructure
of trusted key servers or certificate management. Instead, SRP server
applications use verification keys derived from each user's password
to determine the authenticity of a network connection.

SRP provides mutual-authentication in that successful authentication
requires both sides of the connection to have knowledge of the
user's password. If the client side lacks the user's password or the
server side lacks the proper verification key, the authentication will
fail.

Unlike SSL, SRP does not directly encrypt all data flowing through
the authenticated connection. However, successful authentication does
result in a cryptographically strong shared key that can be used
for symmetric-key encryption.

For a full description of the pysrp package and the SRP protocol,
please refer to the `srp module documentation`_.

.. _`srp module documentation`: http://packages.python.org/srp

'''

class Tox(TestCommand):
    user_options = [('tox-args=', 'a', "Arguments to pass to tox")]
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import tox
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        errno = tox.cmdline(args=args)
        sys.exit(errno)

ext_modules = [ Extension('srp._srp',
                          ['srp/_srp.c',],
                          libraries = ['ssl',],
                          optional=True) ]

def read_file(filename):
    """Read a file into a string"""
    path = os.path.abspath(os.path.dirname(__file__))
    filepath = os.path.join(path, filename)
    try:
        return open(filepath).read()
    except IOError:
        return ''

setup(name             = 'srp',
      version          = '1.0.4',
      description      = 'Secure Remote Password',
      author           = 'Tom Cocagne',
      author_email     = 'tom.cocagne@gmail.com',
      url              = 'http://code.google.com/p/pysrp/',
      download_url     = 'http://pypi.python.org/pypi/srp',
      long_description = long_description,
      provides         = ['srp'],
      packages         = ['srp'],
      package_data     = {'srp' : ['doc/*.rst', 'doc/*.py']},
      ext_modules      = ext_modules,
      license          = "MIT",
      platforms        = "OS Independent",
      install_requires = read_file('requirements.txt'),
      tests_require    = ['virtualenv', 'tox'],
      cmdclass         = {'test': Tox},
      classifiers      = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: C',
        'Topic :: Security',
        ],)
