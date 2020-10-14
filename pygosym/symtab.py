import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Iterator
from .pclntab import LineTable, ByteOrder, Sym, Obj, Func, SYMS_ENCODING


# https://golang.org/src/debug/gosym/symtab.go


logger = logging.getLogger(__name__)


class DecodingError(Exception):
    pass


@dataclass
class Table:
    syms: List[Sym] = field(default_factory=list)
    funcs: List[Func] = field(default_factory=list)
    files: Dict[str, Obj] = field(default_factory=dict)
    objs: List[Obj] = field(default_factory=list)

    go12line: Optional[LineTable] = None


@dataclass
class sym:
    value: int = 0
    typ: int = 0
    name: bytes = b""
    gotype: int = 0


LITTLE_ENDIAN_SYMTAB     = bytes((0xFD, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00))
BIG_ENDIAN_SYMTAB        = bytes((0xFF, 0xFF, 0xFF, 0xFD, 0x00, 0x00, 0x00))
OLD_LITTLE_ENDIAN_SYMTAB = bytes((0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00))


def walksymtab(data: memoryview) -> Iterator[sym]:
    if len(data) == 0:
        return

    new_table_format = False
    order = ByteOrder.BIG_ENDIAN
    data_magic = data[:7].tobytes()  # for .startswith
    if data_magic.startswith(OLD_LITTLE_ENDIAN_SYMTAB):
        data = data[6:]
        order = ByteOrder.LITTLE_ENDIAN
    elif data_magic.startswith(BIG_ENDIAN_SYMTAB):
        new_table_format = True
    elif data_magic.startswith(LITTLE_ENDIAN_SYMTAB):
        new_table_format = True
        order = ByteOrder.LITTLE_ENDIAN

    ptrsz = 0
    if new_table_format:
        if len(data) < 8:
            raise DecodingError("unexpected EOF")
        ptrsz = data[7]
        if ptrsz not in (4, 8):
            return DecodingError("invalid pointer size")
        data = data[8:]

    s = sym()
    p = data
    while len(p) >= 4:
        typ: int
        if new_table_format:
            # Symbol type, value, Go type.
            typ = p[0] & 0x3F
            wide_value = (p[0] & 0x40) != 0
            go_type = (p[0] & 0x80) != 0
            if typ < 26:
                typ += ord("A")
            else:
                typ += ord("a") - 26
            s.typ = typ
            p = p[1:]

            if wide_value:
                if len(p) < ptrsz:
                    raise DecodingError("unexpected EOF")

                s.value = order.from_bytes(p[0:ptrsz])
                p = p[ptrsz:]
            else:
                s.value = 0
                shift = 0
                while len(p) > 0 and p[0] & 0x80 != 0:
                    s.value |= p[0] & 0x7F << shift
                    shift += 7
                    p = p[1:]
                if len(p) == 0:
                    return DecodingError("unexpected EOF")

                s.value |= p[0] << shift
                p = p[1:]
            if go_type:
                if len(p) < ptrsz:
                    raise DecodingError("unexpected EOF")
                # fixed-width go type
                s.gotype = order.from_bytes(p[0:ptrsz])
                p = p[ptrsz:]
        else:
            # value, symbol type
            s.value = order.from_bytes(p[0:4])
            if len(p) < 5:
                raise DecodingError("unexpected EOF")
            typ = p[4]
            if typ & 0x80 == 0:
                raise DecodingError("bad symbol type")
            typ = typ & ~0x80
            s.typ = typ
            p = p[5:]

        # Name.
        i: int
        nnul: int
        for i in range(len(p)):
            if p[i] == 0:
                nnul = 1
                break

        if typ in b"Zz":
            p = p[i+nnul:]
            for i in range(0, len(p), 2):
                if p[i] == 0 and p[i + 1] == 0:
                    nnul = 2
                    break

        if len(p) < i + nnul:
            raise DecodingError("unexpected EOF")
        s.name = p[0:i].tobytes()
        i += nnul
        p = p[i:]

        if not new_table_format:
            if len(p) < 4:
                raise DecodingError("unexpected EOF")
            s.gotype = order.from_bytes(p[:4])
            p = p[4:]

        yield s


def new_table(symtab: memoryview, pcln: LineTable) -> Optional[Table]:
    t = Table()
    if pcln.go12 is not None:
        go12 = pcln.go12
        t.go12line = pcln

    fname: Dict[int, str] = {}
    nf = 0
    nz = 0
    lasttyp = 0

    for s in walksymtab(symtab):
        ts = Sym()
        t.syms.append(ts)
        ts.type = s.typ
        ts.value = s.value
        ts.go_type = s.gotype
        if s.typ in b"Zz":
            if lasttyp not in b"Zz":
                nz += 1
            for i in range(0, len(s.name), 2):
                elt_idx = int.from_bytes(s.name[i:i + 2], "big")
                elt = fname.get(elt_idx, None)
                if elt is None:
                    raise DecodingError("bad filename code")
                if ts.name and ts.name[-1] != "/":
                    ts.name += "/"
                ts.name += elt
        else:
            ts.name = s.name.decode(SYMS_ENCODING).replace("·", ".")

        if s.typ in b"f":
            fname[s.value] = ts.name
        elif s.typ in b"TtLl":
            nf += 1
        lasttyp = s.typ

    if t.go12line is not None:
        obj = Obj()
        t.objs = [obj]
        go12.go12_map_files(t.files, obj)
    else:
        t.objs = [Obj() for _ in range(nz)]

    lastf = 0
    i = 0
    while i < len(t.syms):
        sym = t.syms[i]
        # path symbol
        if sym.type in b"Zz":
            # Go 1.2 binaries have the file information elsewhere. Ignore.
            if t.go12line is None:
                i += 1
                continue

            # Finish the current object
            if obj is not None:
                obj.funcs = t.funcs[lastf:]
            lastf = len(t.funcs)

            # Start new object
            obj = Obj()
            t.objs.append(obj)

            # Count & copy path symbols
            for end in range(i + 1, len(t.syms)):
                c = t.syms[end].type
                if c not in b"Zz":
                    break
            obj.paths = t.syms[i:end]
            i = end
            continue
        elif sym.type in b"TtLl":
            if t.funcs:
                t.funcs[-1].end = sym.value
            if sym.name in {"runtime.etext", "etext"}:
                i += 1
                continue

            np = 0
            na = 0
            end = 0
            for end in range(i + 1, len(t.syms)):
                cur_sym_type = t.syms[end].type
                if cur_sym_type in b"TtLlZz":
                    break
                elif cur_sym_type in b"p":
                    np += 1
                elif cur_sym_type in b"a":
                    na += 1

            # Fill in the function symbol
            fn = Func()
            t.funcs.append(fn)
            sym.func = fn
            fn.sym = sym
            fn.entry = sym.value
            fn.obj = obj
            if t.go12line is not None:
                # All functions share the same line table.
                fn.line_table = t.go12line
            elif pcln is not None:
                fn.line_table = pcln.slice(fn.entry)
                pcln = fn.line_table

            for j in range(i, end):
                ls = t.syms[j]
                if ls.type in b"m":
                    fn.frame_size = s.value
                elif ls.type in b"p":
                    fn.params.append(ls)
                elif ls.type in b"a":
                    fn.locals.append(ls)
            i = end
            continue
        else:
            i += 1

    if t.go12line is not None and nf == 0:
        logger.info("reading go12 symbols")
        t.funcs = go12.go12_funcs(t.go12line)

    if obj is not None:
        obj.funcs = t.funcs[lastf:]

    return t
