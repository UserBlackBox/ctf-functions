from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ctf_functions",
    packages=find_packages(),
    version="0.1.0",
    entry_points={
    },
    author="Ivy Fan-Chiang",
    author_email="userblackbox@tutanota.com",
    description="Python library with functions useful for CTF data analysis/decoding",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/UserBlackBox/ctf_functions",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: BSD License"
        "Natural Language :: English",
    ],
    python_requires='>=3.8',
    install_requires=[]
)
