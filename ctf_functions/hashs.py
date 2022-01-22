"""Module with functions for hashing bytes and strings"""

import hashlib
from typing import Dict


def str_md5(data: str) -> str:
    """Returns hexadecimal representation of md5 hashed string"""
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def bytes_md5(data: bytes) -> str:
    """Returns hexadecimal representation of md5 hashed bytes"""
    return hashlib.md5(data).hexdigest()


def str_sha1(data: str) -> str:
    """Returns hexadecimal representation of sha1 hashed string"""
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def bytes_sha1(data: bytes) -> str:
    """Returns hexadecimal representation of sha1 hashed bytes"""
    return hashlib.sha1(data).hexdigest()


def str_sha224(data: str) -> str:
    """Returns hexadecimal representation of sha224 hashed string"""
    return hashlib.sha224(data.encode("utf-8")).hexdigest()


def bytes_sha224(data: bytes) -> str:
    """Returns hexadecimal representation of sha224 hashed bytes"""
    return hashlib.sha224(data).hexdigest()


def str_sha256(data: str) -> str:
    """Returns hexadecimal representation of sha256 hashed string"""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def bytes_sha256(data: bytes) -> str:
    """Returns hexadecimal representation of sha256 hashed bytes"""
    return hashlib.sha256(data).hexdigest()


def str_sha384(data: str) -> str:
    """Returns hexadecimal representation of sha384 hashed string"""
    return hashlib.sha384(data.encode("utf-8")).hexdigest()


def bytes_sha384(data: bytes) -> str:
    """Returns hexadecimal representation of sha384 hashed bytes"""
    return hashlib.sha384(data).hexdigest()


def str_sha512(data: str) -> str:
    """Returns hexadecimal representation of sha512 hashed string"""
    return hashlib.sha512(data.encode("utf-8")).hexdigest()


def bytes_sha512(data: bytes) -> str:
    """Returns hexadecimal representation of sha512 hashed bytes"""
    return hashlib.sha512(data).hexdigest()


def str_sha3_224(data: str) -> str:
    """Returns hexadecimal representation of sha3-224 hashed string"""
    return hashlib.sha3_224(data.encode("utf-8")).hexdigest()


def bytes_sha3_224(data: bytes) -> str:
    """Returns hexadecimal representation of sha3-224 hashed bytes"""
    return hashlib.sha3_224(data).hexdigest()


def str_sha3_256(data: str) -> str:
    """Returns hexadecimal representation of sha3-256 hashed string"""
    return hashlib.sha3_256(data.encode("utf-8")).hexdigest()


def bytes_sha3_256(data: bytes) -> str:
    """Returns hexadecimal representation of sha3-256 hashed bytes"""
    return hashlib.sha3_256(data).hexdigest()


def str_sha3_384(data: str) -> str:
    """Returns hexadecimal representation of sha3-384 hashed string"""
    return hashlib.sha3_384(data.encode("utf-8")).hexdigest()


def bytes_sha3_384(data: bytes) -> str:
    """Returns hexadecimal representation of sha3-384 hashed bytes"""
    return hashlib.sha3_384(data).hexdigest()


def str_sha3_512(data: str) -> str:
    """Returns hexadecimal representation of sha3-512 hashed string"""
    return hashlib.sha3_512(data.encode("utf-8")).hexdigest()


def bytes_sha3_512(data: bytes) -> str:
    """Returns hexadecimal representation of sha3-512 hashed bytes"""
    return hashlib.sha3_512(data).hexdigest()


def str_all_hashes(data: str) -> Dict[str, str]:
    """Returns a dictionary of hexadecimal representations of all available
    hash algorithms for a given string"""
    return {
            "md5": str_md5(data),
            "sha1": str_sha1(data),
            "sha224": str_sha224(data),
            "sha256": str_sha256(data),
            "sha384": str_sha384(data),
            "sha512": str_sha512(data),
            "sha3_224": str_sha3_224(data),
            "sha3_256": str_sha3_256(data),
            "sha3_384": str_sha3_384(data),
            "sha3_512": str_sha3_512(data),
            }


def bytes_all_hashes(data: bytes) -> Dict[str, str]:
    """Returns a dictionary of hexadecimal representations of all available
    hash algorithms for given bytes"""
    return {
            "md5": bytes_md5(data),
            "sha1": bytes_sha1(data),
            "sha224": bytes_sha224(data),
            "sha256": bytes_sha256(data),
            "sha384": bytes_sha384(data),
            "sha512": bytes_sha512(data),
            "sha3_224": bytes_sha3_224(data),
            "sha3_256": bytes_sha3_256(data),
            "sha3_384": bytes_sha3_384(data),
            "sha3_512": bytes_sha3_512(data),
            }
