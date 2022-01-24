"""Module with functions for manipulating data encodings"""

import base64 as __b64


def base64_encode(data: bytes) -> str:
    """Encode given data using base64"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.b64encode(bytes(data)).decode()


def base64_decode(data: str) -> bytes:
    """Decode base64 encoded string to bytes data"""
    return __b64.b64decode(data)


def base64url_encode(data: bytes) -> str:
    """Encode given data using base64 with url safe alphabet"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.urlsafe_b64encode(bytes(data)).decode()


def base64url_decode(data: str) -> bytes:
    """Decode url safe base64 encoded string to bytes data"""
    return __b64.urlsafe_b64decode(data)


def base32_encode(data: bytes) -> str:
    """Encode given data using base32"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.b32encode(bytes(data)).decode()


def base32_decode(data: str) -> bytes:
    """Decode base32 encoded string to bytes data"""
    return __b64.b32decode(data)


def base16_encode(data: bytes) -> str:
    """Encode given data using base16"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.b16encode(bytes(data)).decode()


def base16_decode(data: str) -> bytes:
    """Decode base16 encoded string to bytes data"""
    return __b64.b16decode(data)
