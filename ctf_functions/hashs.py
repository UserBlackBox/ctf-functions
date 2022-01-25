"""Module with functions for hashing bytes and strings"""

import hashlib as __hashlib
from typing import Dict as __Dict
from typing import List as __List
from typing import Union as __Union


def md5(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of md5 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.md5(data).hexdigest()


def sha1(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha1 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha1(data).hexdigest()



def sha224(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha224 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha224(data).hexdigest()


def sha256(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha256 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha256(data).hexdigest()


def sha384(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha384 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha384(data).hexdigest()


def sha512(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha512 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha512(data).hexdigest()


def sha3_224(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha3-224 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha3_224(data).hexdigest()


def sha3_256(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha3-256 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha3_256(data).hexdigest()


def sha3_384(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha3-384 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha3_384(data).hexdigest()


def sha3_512(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of sha3-512 hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.sha3_512(data).hexdigest()


def blake2b(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of blake2b hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.blake2b(data).hexdigest()


def blake2s(data: __Union[str, bytes]) -> str:
    """Returns hexadecimal representation of blake2s hashed data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __hashlib.blake2s(data).hexdigest()


def all_hashes(data: __Union[str, bytes]) -> __Dict[str, str]:
    """Returns a dictionary of hexadecimal representations of all available
    hash algorithms for given data"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return {
            "md5": md5(data),
            "sha1": sha1(data),
            "sha224": sha224(data),
            "sha256": sha256(data),
            "sha384": sha384(data),
            "sha512": sha512(data),
            "sha3_224": sha3_224(data),
            "sha3_256": sha3_256(data),
            "sha3_384": sha3_384(data),
            "sha3_512": sha3_512(data),
            "blake2b": blake2b(data),
            "blake2s": blake2s(data),
            }


def analyze_hash(hashhex: str) -> __List[str]:
    """Determines possible algorithms that generated
    a hash based on its length"""
    bits = len(hashhex) // 2 * 8
    algos = {
            32: [
                "CRC-32",
            ],
            64: [
                "CRC-64",
            ],
            128: [
                "MD5",
                "MD4",
                "MD2",
            ],
            160: [
                "SHA-1",
            ],
            224: [
                "SHA224",
                "SHA3-224",
            ],
            256: [
                "SHA256",
                "SHA3-256",
                "BLAKE-256",
                "BLAKE2s",
            ],
            384: [
                "SHA384",
                "SHA3-384",
            ],
            512: [
                "SHA512",
                "SHA3-512",
                "BLAKE-512",
                "BLAKE2b",
                "MD6",
                "Whirlpool",
            ]
    }
    if bits not in algos:
        return []
    else:
        return algos[bits]
