import random
from enum import IntEnum, Enum
import sys
from typing import List

import cocotb
from cocotb.clock import Clock
from cocotb.handle import HierarchyObject, SimHandleBase
from cocotb.triggers import FallingEdge, ReadWrite, Timer, RisingEdge, ReadOnly
from cocotb.monitors import Monitor

from xoodyak import Xoodyak, rand_bytes

from valid_ready_interface import ValidReadyDriver, ValidReadyMonitor
from types import SimpleNamespace


class SegmentType(IntEnum):
    @classmethod
    def from_byte(cls, b):
        return SegmentType(b)

    AD = 0b0001
    PT = 0b0100
    CT = 0b0101
    TAG = 0b1000
    KEY = 0b1100
    NPUB = 0b1101
    HM = 0b0111
    HASH_VALUE = 0b1001


class SegmentHeader():
    def __init__(self, segment_type, len, last, eot, eoi, partial=0) -> None:
        self.segment_type = segment_type
        self.segment_len = len
        self.partial = partial
        self.eoi = eoi
        self.eot = eot
        self.last = last

    def __str__(self):
        s = f'{self.segment_type} len={self.segment_len}'
        if self.eoi:
            s += ' EOI'
        if self.eot:
            s += ' EOT'
        if self.last:
            s += ' Last'
        if self.partial:
            s += ' Partial'
        return s

    @classmethod
    def from_word(cls, w):
        sn = (w >> 24) & 0xf
        return SegmentHeader(SegmentType.from_byte((w >> 28) & 0xf), len=(w >> 16) & 0xffff, last=sn & 1, eot=(sn >> 1) & 1, eoi=(sn >> 2) & 1, partial=(sn >> 3) & 1)

    def __int__(self):
        return (int(self.segment_type) << 28) | (self.partial << 27) | (
            self.eoi << 26) | (self.eot << 25) | (self.last << 24) | (self.segment_len & 0xffff)


IO_WIDTH = 32


class Opcode(IntEnum):
    HASH = 0b1000
    ENC = 0b0010
    DEC = 0b0011
    LDKEY = 0b0100
    ACTKEY = 0b0111


class Instruction:
    def __init__(self, op_code) -> None:
        self.op_code = op_code

    @classmethod
    def from_word(cls, w):
        return Instruction(op_code=Opcode((w >> 12) & 0xf))

    def __int__(self):
        return int(self.op_code) << (IO_WIDTH - 4)


class Tb:
    def __init__(self, dut: SimHandleBase, input_buses: List[str], output_buses: List[str], debug=False, clk_period=10) -> None:
        self.dut = dut
        if hasattr(dut, 'rst_n'):
            self.reset_val = 0
            self.reset = dut.rst_n
        else:
            self.reset_val = 1
            self.reset = dut.rst
        self.clock = dut.clk
        self.clk_period = clk_period
        self.clkedge = RisingEdge(self.clock)
        self.drivers = SimpleNamespace(**{k: ValidReadyDriver(dut, k, self.clock, debug=debug) for k in input_buses})
        self.monitors = {k: ValidReadyMonitor(dut, k, self.clock, debug=debug) for k in output_buses}

    async def reset_dut(self, duration):
        self.reset <= self.reset_val
        await Timer(duration)
        self.reset <= ~(self.reset_val)
        self.reset._log.debug("Reset complete")
        await self.clkedge
        await self.clkedge

    async def start(self):
        clock = Clock(self.clock, period=self.clk_period)
        cocotb.fork(clock.start())
        await cocotb.fork(self.reset_dut(2.5*self.clk_period))
        for _mon_name, mon in self.monitors.items():
            cocotb.fork(mon())


class LwcTb(Tb):
    def __init__(self, dut: SimHandleBase, debug=False) -> None:
        super().__init__(dut, input_buses=['pdi', 'sdi'], output_buses=['pdo'], debug=debug)

    @staticmethod
    def bytes_to_words(x: bytes, word_bytes=4):
        last = len(x)
        return [int.from_bytes(x[i:min(i + word_bytes, last)], 'little') for i in range(0, len(x), word_bytes)]

    async def send_segment(self, segment_type, segment_data):
        sender = self.drivers.pdi
        eoi = 0  # not required
        last = 0
        if segment_type == SegmentType.KEY:
            sender = self.drivers.sdi
            eoi = 1
            last = 1
        if segment_type == SegmentType.CT or segment_type == SegmentType.PT or segment_type == SegmentType.HM:
            last = 1
            eoi = 1
        # TODO FIXME multi segment
        await sender(SegmentHeader(segment_type, len(segment_data), last=last, eot=1, eoi=eoi))
        for w in self.bytes_to_words(segment_data):
            await sender(w)


class OpCode(IntEnum):
    Encrypt = 0
    Decrypt = 1
    Hash = 2


@cocotb.test()
async def test_dut(dut: SimHandleBase):
    ref = Xoodyak()

    tb = LwcTb(dut, debug=True)
    await tb.start()

    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    nonce = bytes.fromhex('101112131415161708090A0B0C0D0E0F')
    ad = bytes.fromhex('567811')
    pt = bytes.fromhex('123411')

    ref.encrypt(pt, ad, nonce, key)

    await tb.drivers.pdi(Instruction(Opcode.ACTKEY))

    await tb.drivers.sdi(Instruction(Opcode.LDKEY))  # nonsense!
    await tb.send_segment(SegmentType.KEY, key)

    await tb.drivers.pdi(Instruction(Opcode.ENC))
    await tb.send_segment(SegmentType.NPUB, nonce)
    await tb.send_segment(SegmentType.AD, ad)
    await tb.send_segment(SegmentType.PT, pt)

    for _ in range(30):
        await tb.clkedge
