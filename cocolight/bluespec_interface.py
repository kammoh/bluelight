from typing import Any, Dict, Optional, Union

from cocotb.handle import HierarchyObject, ModifiableObject
from cocotb.triggers import GPITrigger, ReadWrite, RisingEdge


class BsvType:
    def __init__(self) -> None:
        # self.bits: Optional[int] = None
        pass

    def pack(self, v) -> int:
        return int(v)


class BsvBits(BsvType):
    def __init__(self, bits: int) -> None:
        self.bits = bits

    def pack(self, v: Union[int, bytes]) -> int:
        mask = (1 << self.bits) - 1
        if isinstance(v, bytes):
            v = int.from_bytes(v, "little")
        return int(v) & mask

    def __call__(self, v) -> int:
        return self.pack(v)


class BsvBool(BsvBits):
    def __init__(self) -> None:
        BsvBits.__init__(self, 1)


class BsvStruct(BsvType):
    def __init__(self, **struct_def) -> None:
        self.struct_def = struct_def
        self.bits = 0
        for _, typ in struct_def.items():
            self.bits += typ.bits

    def pack(self, v: Dict[str, Any]) -> int:
        x = 0
        for name, typ in self.struct_def.items():
            sv = typ.pack(v.get(name, 0))
            x = (x << typ.bits) | sv
        return x

    def __call__(self, **kwds: Any) -> int:
        return self.pack(kwds)


class BsvSignal:
    def __init__(self, handle: ModifiableObject, typ: BsvType) -> None:
        self.handle: ModifiableObject = handle
        self.typ: BsvType = typ


class ActionMethod:
    def __init__(
        self,
        name: str,
        dut: HierarchyObject,
        clock_edge: Optional[GPITrigger] = None,
    ) -> None:
        self.prefix = name
        self.dut = dut
        self.log = dut._log

        self.en: ModifiableObject = getattr(dut, "EN_" + name)
        self.rdy: ModifiableObject = getattr(dut, "RDY_" + name)
        self.return_value_signal: Optional[ModifiableObject] = getattr(dut, name, None)

        if clock_edge is None:
            clock = None
            for c in ["clk", "CLK", "clock"]:
                if hasattr(self.dut, c):
                    clock = getattr(self.dut, c)
                    break
            assert clock
            clock_edge = RisingEdge(clock)
        self.clock_edge = clock_edge
        self.en.setimmediatevalue(0)

    async def __call__(self, **kwargs):
        await ReadWrite()  # ???
        while self.rdy.value != 1:
            await RisingEdge(self.rdy)
        self.en.value = 1
        for name, value in kwargs.items():
            # self.log.info("setting %s to %s", name, value)
            handle = getattr(self.dut, self.prefix + "_" + name)
            handle.value = value
        await self.clock_edge
        self.en.value = 0
        if self.return_value_signal:
            return self.return_value_signal.value


def vals2bytes(vals):
    if not isinstance(vals, list):
        vals = [vals]
    b = b""
    for v in vals:
        b += v.buff[::-1]
    return b
