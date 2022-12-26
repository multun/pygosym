# pygosym

A python library to read golang symbol tables.
It has no dependencies, and was ported over from the [gosym package](https://golang.org/src/debug/gosym/) from golang standard library.

# How do I use this library?

Here's an example of how to use it with elftools:

```python

from typing import Optional
from elftools.elf.elffile import ELFFile, Segment
from pygosym import new_line_table, new_table

import sys


def get_first_exec_seg(elf_file: ELFFile) -> Optional[Segment]:
    for seg in elf_file.iter_segments():
        if seg["p_flags"] & 0b001:
            return seg
    return None


def get_text_addr(elf_file) -> Optional[int]:
    text = get_first_exec_seg(elf_file)
    if text is None:
        logger.info("couldn't find an executable section")
        return None

    return text["p_vaddr"]


def go_funcs(elf_file, text_addr):
    lntab_section = elf_file.get_section_by_name(".gopclntab")
    symtab_section = elf_file.get_section_by_name(".gosymtab")
    line_table = new_line_table(lntab_section.data(), text_addr)
    symtab = new_table(memoryview(symtab_section.data()), line_table)
    return symtab.funcs


def load_gofuncs(path):
    with open(path, "rb") as f:
        elf_file = ELFFile(f)
        text_addr = get_text_addr(elf_file)
        if text_addr is None:
            logger.warning("couldn't find .text")
            exit(1)

        return go_funcs(elf_file, text_addr)


if __name__ == "__main__":
    for func in load_gofuncs(sys.argv[1])):
        print(f"{func.sym.value:8x}\t{func.sym.name}")
```
