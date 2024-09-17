import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "EKM-Client",
    version = "1.3",
    author = "SeucreON",
    author_email = "secureon@nexttechnosolutions.com",
    description = ("EKM Client application for making requests to EKM server"),
    keywords = "Encryption & Decryption",
    url = "http://10.0.1.4:8005/ekmclient",
    packages=['ekm'],
    install_requires=[
          'requests','argparse'
      ],
    entry_points = {
        'console_scripts': ['ekmtoken=ekm.client:generate_token'],
    },
    long_description=read('README'),
     include_package_data=True,
     zip_safe=False
)
