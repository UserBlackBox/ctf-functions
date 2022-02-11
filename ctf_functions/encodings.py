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
        if len(hex_encoded[-1]) == 1:
            hex_encoded[-1] = "0" + hex_encoded[-1]
    return delimiter.join(hex_encoded)


def from_hex(hex_data: str, delimiter: str = " ") -> bytes:
    """Converts hexadecimal byte string into bytes object"""
    if delimiter == "":
        data = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]
    else:
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
        bin_encoded[-1] = "0" * (8 - len(bin_encoded[-1])) + bin_encoded[-1]
    return delimiter.join(bin_encoded)


def from_binary(bin_data: str, delimiter: str = " ") -> bytes:
    """Converts binary string into bytes object"""
    if delimiter == "":
        data = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
    else:
        data = bin_data.split(delimiter)
    data = [int(byte, 2) for byte in data]
    return bytes(data)


def to_octal(data: __Union[str, bytes], delimiter: str = " ") -> str:
    """Converts input data to octal string"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    oct_encoded = []
    for char in data:
        oct_encoded.append(oct(char)[2:])
        oct_encoded[-1] = "0" * (3 - len(oct_encoded[-1])) + oct_encoded[-1]
    return delimiter.join(oct_encoded)


def from_octal(oct_data: str, delimiter: str = " ") -> bytes:
    """Converts octal string into bytes object"""
    if delimiter == "":
        data = [oct_data[i:i+3] for i in range(0, len(oct_data), 3)]
    else:
        data = oct_data.split(delimiter)
    return bytes([int(byte, 8) for byte in data])


def to_decimal(data: __Union[str, bytes], delimiter: str = " ") -> str:
    """Converts input data to decimal bytes"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    dec_encode = list(map(str, list(data)))
    for i in range(len(dec_encode)):
        dec_encode[i] = "0" * (3 - len(dec_encode[i])) + dec_encode[i]
    return delimiter.join(dec_encode)


def from_decimal(dec_data: str, delimiter: str = " ") -> bytes:
    """Converts decimal string into bytes object"""
    if delimiter == "":
        data = [dec_data[i:i+3] for i in range(0, len(dec_data), 3)]
    else:
        data = dec_data.split(delimiter)
    return bytes(map(int, data))
