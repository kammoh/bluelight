
from math import ceil
from types import SimpleNamespace
from typing import List
import random

import cocotb
from cocotb.clock import Clock
from cocotb.result import TestError, TestFailure
from cocotb.handle import SimHandleBase
from cocotb.triggers import (Join, ReadOnly, RisingEdge, Timer)

from .hw_api import Instruction, Segment, SegmentType, OpCode, Status

IO_WIDTH = 32


class ValidReadyDriver:
    def __init__(self, dut: SimHandleBase, name: str, clock: SimHandleBase, debug=False, max_stalls=0) -> None:
        self._valid = getattr(dut, f'{name}_valid')
        self._ready = getattr(dut, f'{name}_ready')
        self.name = name
        self.dut = dut
        self.log = dut._log
        self.clock = clock
        self._debug = debug
        self.clock_edge = RisingEdge(clock)
        self.queue = []
        self._forked = None
        self.max_stalls = max_stalls

        self._valid.setimmediatevalue(0)

        # dut._id(f"{sig_name}", extended=False) ?
        self._data_sig = getattr(self.dut, f'{self.name}_data')

        self._width_nibs = (len(self._data_sig) + 3) // 4

    async def run(self):
        for word in self.queue:
            r = random.randint(-self.max_stalls, self.max_stalls)
            if r > 0:
                self._valid <= 0
                for _ in range(r):
                    await self.clock_edge

            self._valid.setimmediatevalue(1)  # TODO constrained random stalls
            word = int(word)
            # if self._debug:
            #     self.log.debug(
            #         f'putting 0x{word:0{self._width_nibs}x} on {self._data_sig._name}')
            self._data_sig <= word
            await ReadOnly()
            # self.log.debug(f'self._ready.value={self._ready.value}')
            while not self._ready.value:
                await self.clock_edge
                await ReadOnly()
            await self.clock_edge
        self._valid.setimmediatevalue(0)

    async def fork(self):
        self._forked = cocotb.fork(self.run())

    async def join(self):
        if self._forked:
            await Join(self._forked)


class ValidReadyMonitor:
    def __init__(self, dut: SimHandleBase, name: str, clock: SimHandleBase, debug=False, max_stalls=0) -> None:
        self._valid = getattr(dut, f'{name}_valid')
        self._ready = getattr(dut, f'{name}_ready')
        self.name = name
        self.dut = dut
        self.log = dut._log
        self.clock = clock
        self.clock_edge = RisingEdge(clock)
        self._ready.setimmediatevalue(0)
        self._data_sig = getattr(self.dut, f'{self.name}_data')
        self.failures = 0
        self.num_received_words = 0
        self._debug = debug
        self.w = ceil(len(self._data_sig) / 4)
        self.expected = []
        self._forked = None
        self.max_stalls = max_stalls

    # TODO just single "data" field implemented

    async def run(self):
        if not self.expected:
            self.log.error(f"Monitor {self.name} is not expecting any data!")
            raise TestError

        # await ReadOnly()
        for exp in self.expected:
            if self._debug:
                self.log.debug(f"expecting 0x{exp:0{self.w}x}")
            # TODO add ready generator
            r = random.randint(-self.max_stalls, self.max_stalls)
            if r > 0:
                self._ready <= 0
                for _ in range(r):
                    await self.clock_edge

            self._ready <= 1
            await ReadOnly()
            while self._valid.value != 1:
                await self.clock_edge  # TODO optimize by wait for valid = 1 if valid was != 0 ?
                await ReadOnly()

            received = self._data_sig.value

            self.num_received_words += 1

            if self._debug:
                # print(f'Received 0x{received:0{self.w}x} from {self._data_sig._name}')
                self.log.debug(f'Received {received} on {self.name}')

            recv_x = False
            try:
                received = int(received)
            except:
                recv_x = True

            # TODO add support for don't cares (X/-) in the expected words (should be binary string then?)
            if recv_x or received != exp:
                self.log.error(
                    f"[monitor:{self.name}] received: 0x{int(received):0{self.w}x} expected: 0x{exp:0{self.w}x}")
                self.failures += 1
            await self.clock_edge

        self._ready <= 0

    async def fork(self):
        self._forked = cocotb.fork(self.run())

    async def join(self):
        if self._forked:
            await Join(self._forked)
            self.log.info(
                f"Monitor {self.name}: joined after receiving {self.num_received_words} words")

        if self.failures > 0:
            self.log.error(
                f"[monitor:{self.name}] Number of Failures: {self.failures}")
            raise TestFailure


class Tb:
    def __init__(self, dut: SimHandleBase, input_buses: List[str], output_buses: List[str], debug=False, clk_period=10, max_in_stalls=0, max_out_stalls=0) -> None:
        self.dut = dut
        self.log = dut._log
        self.started = False
        if hasattr(dut, 'rst_n'):
            self.reset_val = 0
            self.reset = dut.rst_n
        else:
            self.reset_val = 1
            self.reset = dut.rst
        self.clock = dut.clk
        self.clk_period = clk_period
        self.clkedge = RisingEdge(self.clock)
        self.drivers = SimpleNamespace(
            **{k: ValidReadyDriver(dut, k, self.clock, debug=debug, max_stalls=max_in_stalls) for k in input_buses})
        self.monitors = SimpleNamespace(**{bus_name: ValidReadyMonitor(
            dut=dut, name=bus_name, clock=self.clock, debug=debug, max_stalls=max_out_stalls) for bus_name in output_buses})

        self._forked_clock = None

    async def reset_dut(self, duration):
        self.reset <= self.reset_val
        await Timer(duration)
        self.reset <= ~(self.reset_val)
        await self.clkedge
        self.log.debug("Reset complete")

    async def start(self):
        if not self.started:
            clock = Clock(self.clock, period=self.clk_period)
            self._forked_clock = cocotb.fork(clock.start())
            await cocotb.fork(self.reset_dut(2.5*self.clk_period))
            self.started = True

    async def launch_monitors(self):
        for mon in self.monitors.__dict__.values():
            self.log.info(f"Forking monitor {mon.name}")
            await mon.fork()

    async def launch_drivers(self):
        for driver in self.drivers.__dict__.values():
            self.log.info(f"Forking driver {driver.name}")
            await driver.fork()

    async def join_monitors(self):
        for mon in self.monitors.__dict__.values():
            await mon.join()

    async def join_drivers(self):
        for driver in self.drivers.__dict__.values():
            await driver.join()


class LwcTb(Tb):
    def __init__(self, dut: SimHandleBase, debug=False, max_in_stalls=0, max_out_stalls=0) -> None:
        super().__init__(dut=dut,
                         input_buses=['pdi', 'sdi'], output_buses=['do'], debug=debug, max_in_stalls=0, max_out_stalls=0)
        self.io_width = IO_WIDTH  # FIXME auto get and check from pdi sdi do

    def enqueue(self, instruction: Instruction, *segments: Segment):
        width = self.io_width
        sender = self.drivers.sdi if instruction.op == OpCode.LDKEY else self.drivers.pdi

        # self.log.debug(f'enqueuing instruction {instruction} on {sender.name}')
        sender.queue.extend(instruction.to_words(width))
        last_idx = len(segments) - 1
        for i, segment in enumerate(segments):
            last = i == last_idx

            segment.header.last = last

            eoi = last
            if not last:
                eoi = True
                for x in segments[i+1:]:
                    if x.len and x.type not in {SegmentType.TAG, SegmentType.LENGTH}:
                        eoi = False
                        break

            segment.header.last = last
            segment.header.eoi = eoi
            segment.header.eot = last or segments[i+1].type != segment.type

            # TODO FIXME multi segment
            # self.log.info(
            #     f'enqueuing segment {segment.header} on {sender.name}')
            sender.queue.extend(segment.to_words(width))

    def expect_segment(self, *segments: Segment):
        for segment in segments:
            exp_words = segment.to_words(self.io_width)
            # self.log.debug(
            #     f'adding expected words: {[f"0x{w:08x}" for w in exp_words]}')
            self.monitors.do.expected.extend(exp_words)

    def expect_status_success(self):
        self.monitors.do.expected.extend(
            Status.Success.to_words(self.io_width))

    def encrypt_test(self, key, nonce, ad, pt, ct, tag):
        self.enqueue(Instruction(OpCode.ACTKEY))
        self.enqueue(Instruction(OpCode.LDKEY),
                     *Segment.segmentize(SegmentType.KEY, key))
        self.enqueue(Instruction(OpCode.ENC),
                     *Segment.segmentize(SegmentType.NPUB, nonce),
                     *Segment.segmentize(SegmentType.AD, ad),
                     *Segment.segmentize(SegmentType.PT, pt))

        # EOI is set to ‘0’ for output segments
        self.expect_segment(
            *Segment.segmentize(SegmentType.CT, ct, last=0, eot=1, eoi=0))
        self.expect_segment(
            *Segment.segmentize(SegmentType.TAG, tag, last=1, eot=1, eoi=0))
        self.expect_status_success()

    def decrypt_test(self, key, nonce, ad, pt, ct, tag):
        self.enqueue(Instruction(OpCode.ACTKEY))
        self.enqueue(Instruction(OpCode.LDKEY),
                     *Segment.segmentize(SegmentType.KEY, key))
        self.enqueue(Instruction(OpCode.DEC),
                     *Segment.segmentize(SegmentType.NPUB, nonce),
                     *Segment.segmentize(SegmentType.AD, ad),
                     *Segment.segmentize(SegmentType.CT, ct),
                     *Segment.segmentize(SegmentType.TAG, tag)
                     )

        self.expect_segment(Segment(SegmentType.PT, pt, last=1, eot=1, eoi=0))
        self.expect_status_success()

    def hash_test(self, hm, digest):
        self.enqueue(Instruction(OpCode.HASH),
                     *Segment.segmentize(SegmentType.HM, hm)
                     )

        self.expect_segment(*Segment.segmentize(SegmentType.DIGEST, digest, last=1, eot=1, eoi=0))
        self.expect_status_success()
