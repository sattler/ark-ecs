# -----------------------------------------------------------------------------
# Copyright (c) 2025 Patrick Sattler
#
# This file is part of ECSplorer for Ark.
#
# This code is licensed under the Mozilla Public License, version 2.0 (MPL 2.0).
# You may not use this file except in compliance with the License.
# You can obtain a copy of the License at:
#
#    https://www.mozilla.org/en-US/MPL/2.0/
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

import ipaddress
from enum import Enum

class PrefixType(Enum):
    UNANNOUNCED = 0
    SPECIAL = 1
    BGPANNOUNCED = 2

class ScanningMode(Enum):
    SAMPLE_MODE = 0
    BGP_MODE = 1
    BGP_PREFIX_MODE = 2
    FINISHED_SCANNING = 3

def bytes_for_ip_version(is_ipv6: bool) -> int:
    return 16 if is_ipv6 else 4

def convert_ip_from_net_ip_to_field(ip: ipaddress.ip_address) -> list[int]:
    ip_bytes = ip.packed
    as_field = []

    for byte in ip_bytes:
        as_field.extend(1 if byte & (1 << j) else 0 for j in range(7, -1, -1))

    return as_field

def convert_ip_from_field_to_net_ip(ip_as_field: list[int], is_ipv6: bool) -> str:
    ip_bytes = bytes_for_ip_version(is_ipv6)
    while len(ip_as_field) < ip_bytes * 8:
        ip_as_field.append(0)

    bytes_of_ip = bytearray(ip_bytes)

    for i in range(ip_bytes):
        x = 0
        for j in range(8):
            x = (x << 1) + ip_as_field[i * 8 + j]
        bytes_of_ip[i] = x

    return str(ipaddress.ip_address(int.from_bytes(bytes_of_ip, byteorder='big')))

def convert_ip_from_string_to_key_int(ip_as_string: str) -> int:
    ip_obj = ipaddress.ip_address(ip_as_string)
    ip_as_int = 0
    for i, byte_value in enumerate(ip_obj.packed[:8]):
        ip_as_int = (ip_as_int << 8) + byte_value
    return ip_as_int

def convert_ip_from_short_field_to_key_int(ip_as_short_field: list[int], is_ipv6: bool) -> int:
    ip_as_int = 0
    for bit in ip_as_short_field:
        ip_as_int = (ip_as_int << 1) + bit

    ip_bytes = bytes_for_ip_version(is_ipv6) // 2 if is_ipv6 else bytes_for_ip_version(is_ipv6)
    for _ in range(ip_bytes * 8 - len(ip_as_short_field)):
        ip_as_int <<= 1

    return ip_as_int

def convert_ip_from_short_field_to_ip_network(ip_as_short_field: list[int], is_ipv6: bool) -> ipaddress.ip_address:
    ip_int = convert_ip_from_short_field_to_key_int(ip_as_short_field, is_ipv6)
    return ipaddress.ip_network((ip_int, len(ip_as_short_field)))


def calculate_biggest_key_in_subnet(ip_as_short_field: list[int], is_ipv6: bool) -> int:
    ip_as_int = 0
    for bit in ip_as_short_field:
        ip_as_int = (ip_as_int << 1) + bit

    ip_bytes = bytes_for_ip_version(is_ipv6) // 2 if is_ipv6 else bytes_for_ip_version(is_ipv6)
    for _ in range(ip_bytes * 8 - len(ip_as_short_field)):
        ip_as_int = (ip_as_int << 1) | 1

    return ip_as_int


def first_bits_of_ip_as_field(scope: int, ip: list[int]) -> list[int]:
    return ip[:scope]

def ensure_concatenating_with_zeros(ip: str, scope: int, is_ipv6: bool) -> str:
    ip_obj = ipaddress.ip_address(ip)
    ip_bytes = bytes_for_ip_version(is_ipv6)

    mask = (1 << (ip_bytes * 8)) - (1 << (ip_bytes * 8 - scope))
    masked_ip = int(ip_obj) & mask

    return str(ipaddress.ip_address(masked_ip))
