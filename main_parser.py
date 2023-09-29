#!/usr/bin/env python3

import sys
import re
import math

intelhex_re = re.compile(r"^:(?P<byte_count>[0-9A-F]{2})(?P<address>[0-9A-F]{4})(?P<rec_type>[0-9A-F]{2})(?P<data>[0-9A-F]{0,510}?)(?P<checksum>[0-9A-F]{2})$\s*", flags=re.IGNORECASE)

def get_args():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} path_to_intel_hex")
        exit(1)

    return sys.argv[1]


def calc_checksum(m):
    # get all bytes except checksum
    all_bytes = "".join(m.groups()[:-1])

    # separate each byte, parse it as int and get sum
    hex_bytes = [int(all_bytes[i]+all_bytes[i+1], 16) for i in range(0, len(all_bytes), 2)]
    num = sum(hex_bytes)

    return (~num + 1) & 0xff


def parse_line(line):
    parsed_data = b""
    addr = math.inf
    m = intelhex_re.fullmatch(line)

    if not m:
        raise Exception(f"Invalid Intel Hex format line found: {line}")

    byte_count = int(m.group("byte_count"), 16)
    
    rec_type = int(m.group("rec_type"), 16)
    checksum = int(m.group("checksum"), 16)


    # check for valid checksum
    if checksum != calc_checksum(m):
        print("[!] Invalid checksum at line '{line}'")

    # check if it's end of line
    # byte_count == 0 && rec_type == 1
    if not byte_count and rec_type:
        return addr, parsed_data
    
    # otherwise regular operation, parse data
    # rec_type == 0
    elif not rec_type:
        addr = int(m.group("address"), 16)
        parsed_data = int(m.group("data"), 16).to_bytes(byte_count, byteorder="big")

    return addr, parsed_data


if __name__ == "__main__":
    hex_path = get_args()
    hex_path_base = hex_path.split(".")[0]

    with open(hex_path, "r") as hex_f, open(f"{hex_path_base}.bin", "+wb") as bin_f:
        # parse line through line, sort it with given addresses, and write into file
        parsed_data = map(parse_line, hex_f.readlines())
        sorted_data = [bin_f.write(data) for _, data in sorted(parsed_data)]

    print(f"[+] Written data into file: {hex_path_base}.bin")
    