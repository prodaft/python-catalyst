from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="python-catalyst",
    version="0.1.4",
    description="Python client for the PRODAFT CATALYST API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="PRODAFT",
    author_email="catalyst+pypi@prodaft.com",
    url="https://github.com/prodaft/python-catalyst",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "stix2>=3.0.0",
        "python-dateutil>=2.9.0",
        "pycti>=6.5.8",
    ],
    tests_require=[
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "pytest-mock>=3.10.0",
    ],
    test_suite="tests",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    project_urls={
        "Bug Tracker": "https://github.com/prodaft/python-catalyst/issues",
        "Documentation": "https://github.com/prodaft/python-catalyst",
        "Source Code": "https://github.com/prodaft/python-catalyst",
    },
    keywords="prodaft, catalyst, threat intelligence, stix, opencti",
)
