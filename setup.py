#!/usr/bin/env python
"""Cloud Provider Interface Package

JASMIN Cloud Project
"""
__author__ = "P J Kershaw"
__date__ = "14/04/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
   
from os import path


THIS_DIR = path.dirname(__file__)
_long_description = open(path.join(THIS_DIR, 'README.rst')).read()

setup(
    name='jasmincloud-provider-iface',
    version='0.0.1',
    description=('Client interface to multiple cloud providers '
                 'particularly vCloud, builds on Apache Libcloud'),
    long_description=_long_description,
    author='Philip Kershaw',
    author_email='Philip.Kershaw@stfc.ac.uk',
    maintainer='Philip Kershaw',
    maintainer_email='Philip.Kershaw@stfc.ac.uk',
    url='http://jasmin.ac.uk/',
    license='BSD - see LICENSE file',
    packages=find_packages(),
    namespace_packages=['jasmincloud', 'jasmincloud.provider',
                        'jasmincloud.provider.vcloud'],
    install_requires=['apache-libcloud', 'iptools'],
    entry_points={
    'console_scripts': [
        ('jasmincloud-netclnt=jasmincloud.provider.vcloud.network.'
         'command_line_client:main'),
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe=False
)
