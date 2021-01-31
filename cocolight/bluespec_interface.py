from cocolight.utils import rand_bytes
from typing import Dict, Tuple
from typeguard import typechecked
import inspect
import sys
import os
from pathlib import Path
import cocotb
from cocotb.clock import Clock
from cocotb.handle import HierarchyObject, NonHierarchyObject, SimHandleBase
from cocotb.triggers import ClockCycles, GPITrigger, ReadOnly, ReadWrite, RisingEdge, _EdgeBase

class BsvType:
    def __init__(self) -> None:
        self.bits = None

    def pack(self, v) -> int:
        return int(v)

        
class BsvBits(BsvType):
    def __init__(self, bits: int) -> None:
        self.bits = bits

    def pack(self, v: bytes) -> int:
        if isinstance(v, bytes):
            return int.from_bytes(v, 'little')
        return int(v)

class BsvBool(BsvBits):
    def __init__(self) -> None:
        BsvBits.__init__(self, 1)

class BsvStruct(BsvType):
    def __init__(self, **struct_def) -> None:
        self.struct_def = struct_def
        self.bits = 0
        for _, typ in struct_def.items():
            self.bits += typ.bits

    def pack(self, **struct_values) -> int:
        v = 0
        for name, typ in self.struct_def.items():
            mask = (1 << typ.bits) - 1
            sv = struct_values.get(name, 0)
            if isinstance(sv, bytes):
                sv = int.from_bytes(sv, 'little')
            v = (v << typ.bits) | (sv & mask)
        return v

class BsvSignal:
    def __init__(self, handle: NonHierarchyObject, typ: BsvType) -> None:
        self.handle = handle
        self.typ: BsvType = typ

class ActionMethod:
    def __init__(self, prefix: str, dut: HierarchyObject, args: Dict[str, BsvType] = {}, clock_edge: GPITrigger = None) -> None:
        self.prefix = prefix
        self.dut = dut
        self.log = dut._log

        def sig(s: str, notexist = None, check = False):
            if not hasattr(dut, s):
                if check:
                    raise AttributeError
                return notexist
            return getattr(dut, s)

        self.en = sig('EN_' + prefix, check=True)
        self.rdy = sig('RDY_' + prefix, check=True)
        self.args = {name: BsvSignal(sig(prefix + '_' + name, check=True), typ) for name, typ in args.items()}
        self.return_value_signal = sig(prefix)

        if clock_edge is None:
            clock = None
            for c in ['clk', 'CLK', 'clock']:
                clock = sig(c)
                if clock:
                    break
            assert clock
            clock_edge = RisingEdge(clock)
        self.clock_edge = clock_edge

    async def __call__(self, **kwargs):
        self.en <= 0
        await ReadWrite()
        if self.rdy.value != 1:
            await RisingEdge(self.rdy)
        self.en <= 1
        for name, sig in self.args.items():
            sig.handle <= sig.typ.pack(kwargs.get(name, 0))
        assert self.rdy.value == 1
        await self.clock_edge
        r = self.return_value_signal.value if self.return_value_signal else None
        self.en <= 0
        return r

def vals2bytes(vals):
    if not isinstance(vals, list):
        vals = [vals]
    b = b''
    for v in vals:
        b += v.buff[::-1]
    return b