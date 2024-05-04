#!/usr/bin/env python

from distutils.core import setup, Extension
from distutils.command.install_data import install_data

setup(name='perfmon',
      version='4.0',
      author='Arun Sharma',
      author_email='arun.sharma@google.com',
      description='libpfm wrapper',
      packages=['perfmon'],
      package_dir={ 'perfmon' : 'src' },
      py_modules=['perfmon.perfmon_int'],
      ext_modules=[Extension('perfmon._perfmon_int',
                  sources = ['src/perfmon_int.i'],
                  libraries = ['pfm'],
                  library_dirs = ['../lib'],
                  include_dirs = ['../include'],
                  swig_opts=['-I../include'])])
