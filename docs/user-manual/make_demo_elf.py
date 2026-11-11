# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Write a tiny, deterministic x86-64 ELF for the user-manual walkthrough.

The executable contains two functions: add_one(41) returns 42, and _start
exits with that value. It uses only Python's standard library and is intended
for static analysis in a disposable Ghidra project, not for execution.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


BASE = 0x400000
TEXT_OFFSET = 0x1000
TEXT_ADDR = BASE + TEXT_OFFSET
ADD_ONE = bytes.fromhex("55 48 89 e5 89 f8 83 c0 01 5d c3")
START = bytes.fromhex("bf 29 00 00 00 e8 e6 ff ff ff 89 c7 b8 3c 00 00 00 0f 05")


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def build() -> bytes:
    text = ADD_ONE + bytes(16 - len(ADD_ONE)) + START
    names = b"\x00add_one\x00_start\x00"
    section_names = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    sym_offset = align(TEXT_OFFSET + len(text), 8)
    str_offset = sym_offset + 3 * 24
    shstr_offset = str_offset + len(names)
    sh_offset = align(shstr_offset + len(section_names), 8)
    total = sh_offset + 5 * 64
    data = bytearray(total)

    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,
        TEXT_ADDR + 16,
        64,
        sh_offset,
        0,
        64,
        56,
        1,
        64,
        5,
        4,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, BASE, BASE, total, total, 0x1000)
    data[TEXT_OFFSET : TEXT_OFFSET + len(text)] = text

    def symbol(index: int, name: int, value: int, size: int) -> None:
        struct.pack_into("<IBBHQQ", data, sym_offset + index * 24, name, 0x12, 0, 1, value, size)

    symbol(1, 1, TEXT_ADDR, len(ADD_ONE))
    symbol(2, names.index(b"_start"), TEXT_ADDR + 16, len(START))
    data[str_offset : str_offset + len(names)] = names
    data[shstr_offset : shstr_offset + len(section_names)] = section_names

    def section(index: int, name: bytes, kind: int, flags: int, address: int,
                offset: int, size: int, link: int = 0, info: int = 0,
                alignment: int = 1, entry_size: int = 0) -> None:
        struct.pack_into(
            "<IIQQQQIIQQ",
            data,
            sh_offset + index * 64,
            section_names.index(name),
            kind,
            flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        )

    section(1, b".text", 1, 6, TEXT_ADDR, TEXT_OFFSET, len(text), alignment=16)
    section(2, b".symtab", 2, 0, 0, sym_offset, 72, link=3, info=1, alignment=8, entry_size=24)
    section(3, b".strtab", 3, 0, 0, str_offset, len(names))
    section(4, b".shstrtab", 3, 0, 0, shstr_offset, len(section_names))
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Path for demo_add_one.elf")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(build())
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
