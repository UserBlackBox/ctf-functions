"""Module with functions for manipulating data encodings"""

import base64 as __b64
import urllib.parse as __ulp
from typing import Union as __Union


def base64_encode(data: __Union[str, bytes]) -> str:
    """Encode given data using base64"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.b64encode(bytes(data)).decode()


def base64_decode(data: str) -> bytes:
    """Decode base64 encoded string to bytes data"""
    return __b64.b64decode(data)


def base64url_encode(data: __Union[str, bytes]) -> str:
    """Encode given data using base64 with url safe alphabet"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.urlsafe_b64encode(bytes(data)).decode()


def base64url_decode(data: str) -> bytes:
    """Decode url safe base64 encoded string to bytes data"""
    return __b64.urlsafe_b64decode(data)


def base32_encode(data: __Union[str, bytes]) -> str:
    """Encode given data using base32"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.b32encode(bytes(data)).decode()


def base32_decode(data: str) -> bytes:
    """Decode base32 encoded string to bytes data"""
    return __b64.b32decode(data)


def base16_encode(data: __Union[str, bytes]) -> str:
    """Encode given data using base16"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return __b64.b16encode(bytes(data)).decode()


def base16_decode(data: str) -> bytes:
    """Decode base16 encoded string to bytes data"""
    return __b64.b16decode(data)


def url_encode(string: str, escape_all: bool = False) -> str:
    """Encodes a string to be url safe"""
    if escape_all:
        return __ulp.quote(string, safe="")
    return __ulp.quote(string)


def url_decode(string: str) -> str:
    """Decodes a url escaped string"""
    return __ulp.unquote(string)


def to_hex(data: __Union[str, bytes], delimiter: str = " ") -> str:
    """Converts input data to hexadecimal bytes"""
    hex_encoded = []
    if isinstance(data, str):
        data = data.encode('utf-8')
    for char in data:
        hex_encoded.append(hex(char)[2:])
    return delimiter.join(hex_encoded)


def from_hex(hex_data: str, delimiter: str = " ") -> bytes:
    """Converts hexadecimal byte string into bytes object"""
    data = hex_data.split(delimiter)
    data = [int(byte, 16) for byte in data]
    return bytes(data)


def to_binary(data: __Union[str, bytes], delimiter: str = " ") -> str:
    """Converts input data to a binary string"""
    bin_encoded = []
    if isinstance(data, str):
        data = data.encode('utf-8')
    for char in data:
        bin_encoded.append(bin(char)[2:])
    return delimiter.join(bin_encoded)


def from_binary(bin_data: str, delimiter: str = " ") -> bytes:
    """Converts binary string into bytes object"""
    data = bin_data.split(delimiter)
    data = [int(byte, 2) for byte in data]
    return bytes(data)


def to_decimal(data: __Union[str, bytes], delimiter: str = " ") -> str:
    """Converts input data to decimal bytes"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return delimiter.join(map(str, list(data)))


def from_decimal(dec_data: str, delimiter: str = " ") -> bytes:
    """Converts decimal string into bytes object"""
    return bytes(map(int, dec_data.split(delimiter)))
