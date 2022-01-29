"""Module with utility functions for loading file data"""


def open_text_file(path: str) -> str:
    """Opens text file to string"""
    f = open(path, "r")
    return f.read()


def open_bytes_file(path: str) -> bytes:
    """Opens file to bytes object"""
    f = open(path, "rb")
    return f.read()
