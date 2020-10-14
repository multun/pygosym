import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Tuple


# ported over from
# https://golang.org/src/debug/gosym/pclntab.go


SYMS_ENCODING = "utf-8"


logger = logging.getLogger(__name__)


@dataclass
class Sym:
    value: int = 0
    type: int = 0
    name: str = ""
    go_type: int = 0
    func: Optional["Func"] = field(default=None, repr=False)


@dataclass
class Func(Sym):
    sym: Sym = field(default_factory=Sym)
    entry: int = 0
    end: int = 0
    params: List[Sym] = field(default_factory=list)
    locals: List[Sym] = field(default_factory=list)
    frame_size: int = 0
    line_table: Optional["LineTable"] = field(default=None, repr=False)
    obj: Optional["Obj"] = None


@dataclass
class Obj:
    funcs: List[Func] = field(default_factory=list, repr=False)
    paths: Optional[List[Sym]] = None


class ByteOrder(Enum):
    LITTLE_ENDIAN = "little"
    BIG_ENDIAN = "big"

    def from_bytes(self, b: memoryview) -> int:
        return int.from_bytes(b, self.value)

    def u32(self, b: memoryview) -> int:
        return self.from_bytes(b[:4])

    def u64(self, b: memoryview) -> int:
        return self.from_bytes(b[:8])

    def to_bytes(self, i: int, length: int) -> bytes:
        return i.to_bytes(length, self.value)


@dataclass
class Go12State:
    functab: memoryview
    filetab: memoryview

    binary: ByteOrder = ByteOrder.LITTLE_ENDIAN

    quantum: int = 0
    ptrsize: int = 0

    nfunctab: int = 0
    nfiletab: int = 0

    file_map: Dict[str, int] = field(default_factory=dict)
    strings: Dict[int, str] = field(default_factory=dict)

    def uintptr(self, b: memoryview) -> int:
        return self.binary.from_bytes(b[:self.ptrsize])

    def string(self, data: memoryview, off: int) -> str:
        res = self.strings.get(off, None)
        if res is not None:
            return res

        # strlen
        size = 0
        for b in data[off:]:
            if b == 0:
                break
            size += 1

        res = data[off:off + size].tobytes().decode(SYMS_ENCODING)

        self.strings[off] = res
        return res

    # initFileMap initializes the map from file name to file number.
    def init_file_map(self) -> None:
        if self.file_map is not None:
            return

        self.file_map = {
            self.string(self.binary.u32(self.filetab[4 * i:])): i
            for i in range(1, self.nfiletab)
        }

    # go12MapFiles adds to m a key for every file in the Go 1.2 LineTable.
    # Every key maps to obj. That's not a very interesting map, but it provides
    # a way for callers to obtain the list of files in the program.
    def go12_map_files(self, m: Dict[str, Obj], obj: Obj) -> None:
        self.init_file_map()
        for file_name in self.file_map.keys():
            m[file_name] = obj

    def go12_funcs(self, line_table: "LineTable") -> List[Func]:
        data = line_table.data
        n = len(self.functab) // self.ptrsize // 2
        funcs = []
        for i in range(n):
            entry = self.uintptr(self.functab[2 * i * self.ptrsize:])
            end = self.uintptr(self.functab[(2 * i + 2) * self.ptrsize:])
            info = data[self.uintptr(self.functab[(2 * i + 1) * self.ptrsize:]):]
            frame_size = self.binary.u32(info[self.ptrsize + 2 * 4:])
            funcs.append(Func(
                sym=Sym(
                    value=entry,
                    type=ord("T"),
                    name=self.string(data, self.binary.u32(info[self.ptrsize:])),
                    go_type=0,
                ),
                entry=entry,
                end=end,
                line_table=line_table,
                frame_size=frame_size,
            ))
        return funcs


# NOTE(rsc): This is wrong for GOARCH=arm, which uses a quantum of 4,
# but we have no idea whether we're using arm or not. This only
# matters in the old (pre-Go 1.2) symbol table format, so it's not worth
# fixing.

OLD_QUANTUM = 1

GO12_MAGIC = 0xfffffffb


@dataclass
class LineTable:
    data: memoryview
    PC: int = 0
    line: int = 0

    checked_go12: bool = False
    _go12: Optional[Go12State] = None

    @property
    def go12(self) -> Optional[Go12State]:
        if not self.checked_go12:
            self.checked_go12 = True
            self.go12_init()
        return self._go12

    def go12_init(self) -> None:
        try:
            # Check header: 4-byte magic, two zeros, pc quantum, pointer size.
            if len(self.data) < 16 or self.data[4] != 0 or self.data[5] != 0 or \
               (self.data[6] != 1 and self.data[6] != 2 and self.data[6] != 4) or \
               (self.data[7] != 4 and self.data[7] != 8):  # pointer size
                logger.info("invalid go12 aux header")
                return

            if int.from_bytes(self.data[:4], "big") == GO12_MAGIC:
                binary = ByteOrder.BIG_ENDIAN
            elif int.from_bytes(self.data[:4], "little") == GO12_MAGIC:
                binary = ByteOrder.LITTLE_ENDIAN
            else:
                logger.info("invalid go12 magic")
                return

            quantum = self.data[6]
            ptrsize = self.data[7]
            nfunctab = binary.from_bytes(self.data[8:8 + ptrsize])
            functab = self.data[8 + ptrsize:]
            functabsize = (nfunctab * 2 + 1) * ptrsize
            fileoff = binary.from_bytes(functab[functabsize:functabsize + 4])
            functab = functab[:functabsize]
            filetab = self.data[fileoff:]
            nfiletab = binary.from_bytes(filetab[:4])
            filetab = filetab[:nfiletab * 4]

            self._go12 = Go12State(
                quantum=quantum,
                ptrsize=ptrsize,
                nfunctab=nfunctab,
                nfiletab=nfiletab,
                functab=functab,
                filetab=filetab,
            )
        # If we panic parsing, assume it's not a Go 1.2 symbol table.
        except Exception:
            raise

    def slice(self, pc: int) -> "LineTable":
        data, pc, line = self.parse(pc, -1)
        return LineTable(data=data, PC=pc, line=line)

    def parse(self, target_pc: int, target_line: int) -> Tuple[memoryview, int, int]:
        # The PC/line table can be thought of as a sequence of
        #  <pc update>* <line update>
        # batches. Each update batch results in a (pc, line) pair,
        # where line applies to every PC from pc up to but not
        # including the pc of the next pair.

        # Here we process each update individually, which simplifies
        # the code, but makes the corner cases more confusing.
        b, pc, line = self.data, self.PC, self.line
        while pc <= target_pc and line != target_line and len(b) > 0:
            code = b[0]
            b = b[1:]
            if code == 0:
                if len(b) < 4:
                    b = b[0:0]
                else:
                    val = int.from_bytes(b[:4], "big")
                    b = b[4:]
                    line += val
            elif code <= 64:
                line += code
            elif code <= 128:
                line -= code - 64
            else:
                pc += OLD_QUANTUM * (code - 128)
                continue
            pc += OLD_QUANTUM
        return b, pc, line


def new_line_table(data: bytes, text: int) -> LineTable:
    return LineTable(data=memoryview(data), PC=text, line=0)
