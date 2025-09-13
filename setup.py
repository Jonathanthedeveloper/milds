#!/usr/bin/env python
"""
Setup script for MLIDS - Multi-Level Intrusion Detection System
"""

from setuptools import setup, find_packages
import os

# Read the contents of README.md
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements.txt
def read_requirements(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Core requirements
requirements = read_requirements('requirements.txt')

# Optional requirements for different features
extras_require = {
    'network': ['scapy>=2.4.0'],
    'analysis': ['pandas>=1.3.0', 'numpy>=1.21.0', 'matplotlib>=3.4.0'],
    'monitoring': ['watchdog>=2.1.0', 'tailer>=0.4.0'],
    'websockets': ['websockets>=10.0'],
    'mfa': ['pyotp>=2.6.0'],
    'all': [
        'scapy>=2.4.0',
        'pandas>=1.3.0',
        'numpy>=1.21.0',
        'matplotlib>=3.4.0',
        'watchdog>=2.1.0',
        'tailer>=0.4.0',
        'websockets>=10.0',
        'pyotp>=2.6.0',
        'pyyaml>=6.0',
        'plotly>=5.0.0',
        'seaborn>=0.11.0'
    ]
}

setup(
    name='mlids',
    version='1.0.0',
    description='Multi-Level Intrusion Detection System',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='MLIDS Team',
    author_email='maintainers@mlids.local',
    url='https://github.com/ORG_OWNER/mlids',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    extras_require=extras_require,
    entry_points={
        'console_scripts': [
            'mlids=mlids.__main__:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
    ],
    keywords='security intrusion-detection monitoring network host application',
    python_requires='>=3.8',
    project_urls={
    'Documentation': 'https://github.com/ORG_OWNER/mlids/docs',
    'Source': 'https://github.com/ORG_OWNER/mlids',
    'Tracker': 'https://github.com/ORG_OWNER/mlids/issues',
    },
)