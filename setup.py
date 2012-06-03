from setuptools import setup, find_packages

setup(
    name="netarch",
    version="0.0",
    author="Neale Pickett",
    author_email="neale@lanl.gov",
    description=("Classes to aid in the dissection of network protocols and cryptanalysis"),
    long_description=open("README.txt").read(),
    license=open("COPYING.txt").read(),
    keywords="network protocol dissection cryptanalysis",
    url="http://woozle.org/~neale/projects/netarch",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 2 :: Only",
        "Topic :: System :: Networking"
    ]
)
