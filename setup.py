#!/usr/bin/env python2

from distutils.core import setup

setup(name='ssdc',
      version='1.2.0',
      description='Clusters files based on their ssdeep hash',
      author='Brian Wallace',
      author_email='bwall9809@gmail.com',
      url='https://github.com/bwall/ssdc',
      requires=['pydeep'],
      scripts=['ssdc'],
      py_modules=['ssdc_lib'])
