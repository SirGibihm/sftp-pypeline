from setuptools import setup, find_packages
from sftp_pypeline._version import __version__
setup(
    name='sftp_pypeline',
    version=__version__,
    description="Quickly set up a robust sftp console based SFTP Downloaded/Uploader",
    author="David Holin",
    url="https://github.com/SirGibihm",
    packages=find_packages(include=['sftp_pypeline']),
    install_requires=[
        "paramiko>=2.10.2",
        "psutil>=5.9.0"
        ],
    entry_points={
        'console_scripts': ['sftp_pypeline=sftp_pypeline.sftp_pypeline:main'],
    },
    setup_requires=['flake8']
)