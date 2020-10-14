from typing import Optional
from elftools.elf.elffile import ELFFile, Segment
from pygosym import new_line_table, new_table

import logging
import sys


LOG_FORMAT = (
    '%(asctime)s'
    '\t%(name)s:%(filename)s:%(lineno)s'
    '\t%(levelname)s'
    '\t%(funcName)s'
    '\t%(message).1024s'
)


logger = logging.getLogger("read_syms")


def init_logging():
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        return

    # the root logger defaults to the WARNING log level.
    # this isn't acceptable as when starting up as debug, all debug messages
    # would be dropped until the root logger is configured. Setting to loglevel
    # to NOTSET causes all messages to be logged.
    root_logger.setLevel(logging.NOTSET)

    formatter = logging.Formatter(fmt=LOG_FORMAT,
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


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


def print_gofuncs(funcs):
    for func in funcs:
        print(f"{func.sym.value:8x}\t{func.sym.name}")


def load_gofuncs(path):
    with open(path, "rb") as f:
        elf_file = ELFFile(f)
        text_addr = get_text_addr(elf_file)
        if text_addr is None:
            logger.warning("couldn't find .text")
            exit(1)

        return go_funcs(elf_file, text_addr)


init_logging()


if __name__ == "__main__":
    print_gofuncs(load_gofuncs(sys.argv[1]))
