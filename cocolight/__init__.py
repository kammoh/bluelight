
from logging import Logger
from math import ceil
from types import SimpleNamespace
from typing import List, Union
import random
from queue import Queue

from cocotb.utils import get_sim_time
from xoodyak.pyxoodyak.lwc_api import LwcAead, LwcHash

import cocotb
from cocotb.clock import Clock
from cocotb.result import TestError, TestFailure
from cocotb.handle import SimHandleBase
from cocotb.triggers import (First, Join, ReadOnly, RisingEdge, Timer)

from .hw_api import Instruction, Segment, SegmentType, OpCode, Status
from .utils import rand_bytes

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]

def show_messages(messages, width):
    num_messages = len(messages)
    digits = width // 4
    for message_idx, words in enumerate(messages):
        lines = [' '.join(l) for l in chunks(
            [f'{word:0{digits}x}' for word in words], 10)]
        preamble = f"[{message_idx+1}/{num_messages}:{len(words)}] "
        preamble = f'{preamble:<12}'
        print(preamble + f'\n{" "*len(preamble)}'.join(lines))


class ForkJoinBase:
    def __init__(self) -> None:
        self._forked = None
        self.name = None
        self.log: Logger = None

    def run(self):
        ...

    async def fork(self):
        self._forked = cocotb.fork(self.run())
        self.log.debug(f"forked {self.name}")

    async def join(self, timeout=None):
        if self._forked is not None:
            if timeout:
                timer = Timer(timeout)
                first = await First(timer, self._forked)
                if first is timer:
                    self.log.error(f"Joining {self.name} timed out! (timeout={timeout})")
                    raise TestFailure(f"timeout")
            else:
                await Join(self._forked)
            self.log.debug(f"joined {self.name}")
            self._forked = None
        else:
            self.log.error(
                f"{self.name} joined without being previously forked!")


class ValidReadyDriver(ForkJoinBase):
    def __init__(self, dut: SimHandleBase, name: str, clock: SimHandleBase, debug=False, max_stalls=0) -> None:
        super().__init__()
        self._valid = getattr(dut, f'{name}_valid')
        self._ready = getattr(dut, f'{name}_ready')
        self.name = name
        self.dut = dut
        self.log = dut._log
        self.clock = clock
        self._debug = debug
        self.clock_edge = RisingEdge(clock)
        self.queue: Queue[List[int]] = Queue()
        self.max_stalls = max_stalls
        # dut._id(f"{sig_name}", extended=False) ?
        self._data_sig = getattr(self.dut, f'{self.name}_data')
        self.width = len(self._data_sig)
        self._valid.setimmediatevalue(0)

    async def run(self):
        signal_name = self._data_sig._name
        while not self.queue.empty():
            message = self.queue.get()
            l = len(message)
            u = "word"
            if l > 1:
                u += "s"
            self.log.debug(f'Putting {l} {u} on {signal_name}')
            for word in message:
                r = random.randint(-self.max_stalls, self.max_stalls)
                if r > 0:
                    self._valid <= 0
                    for _ in range(r):
                        await self.clock_edge

                self._valid <= 1
                word = int(word)
                self._data_sig <= word
                await ReadOnly()
                while not self._ready.value:
                    await self.clock_edge
                    await ReadOnly()
                await self.clock_edge
            self._valid <= 0


class ValidReadyMonitor(ForkJoinBase):
    def __init__(self, dut: SimHandleBase, name: str, clock: SimHandleBase, debug=False, max_stalls=0) -> None:
        super().__init__()
        self._valid = getattr(dut, f'{name}_valid')
        self._ready = getattr(dut, f'{name}_ready')
        self.name = name
        self.dut = dut
        self.log = dut._log
        self.clock = clock
        self.clock_edge = RisingEdge(clock)
        self._data_signal = getattr(self.dut, f'{self.name}_data')
        self.width = len(self._data_signal)
        self.failures = 0
        self.num_received_words = 0
        self._debug = debug
        self.queue: Queue[List[int]] = Queue()
        self.max_stalls = max_stalls
        self._ready.setimmediatevalue(0)

    # TODO just single "data" field implemented

    async def run(self):
        width = len(self._data_signal)
        digits = ceil(width / 4)

        num_verified_messages = 0

        if self.queue.empty():
            self.log.error(f"Monitor {self.name} is not expecting any data!")
            raise TestError

        # await ReadOnly()
        while not self.queue.empty():
            message = self.queue.get()
            num_verified_messages += 1
            self.log.info(f"Verifying message #{num_verified_messages} ({len(message)} words) on '{self.name}'")
            for exp in message:
                # TODO add custom ready generator
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

                received = self._data_signal.value
                self.num_received_words += 1

                exp = f'{exp:0{digits}x}'
                try:
                    received = f'{int(received):0{digits}x}'
                except:  # has Xs etc
                    received = str(received)  # Note: binary string with Xs

                # TODO add support for don't cares (X/-) in the expected words (should be binary string then?)
                if received != exp:
                    self.log.error(
                        f"[monitor:{self.name}] received: {received} expected: {exp}")
                    self.failures += 1
                await self.clock_edge

        self._ready <= 0

    async def join(self, timeout=None):
        await super().join(timeout=timeout)

        if self.num_received_words > 0:
            self.log.info(
                f"Monitor: '{self.name}' joined after receiving {self.num_received_words} words")
        else:
            self.log.error(
                f"Monitor: '{self.name}' joined without receiving any data")
            raise TestError

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
        self.clock_period = clk_period
        self.clock_edge = RisingEdge(self.clock)
        self.drivers = SimpleNamespace(
            **{k: ValidReadyDriver(dut, k, self.clock, debug=debug, max_stalls=max_in_stalls) for k in input_buses})
        self.monitors = SimpleNamespace(**{bus_name: ValidReadyMonitor(
            dut=dut, name=bus_name, clock=self.clock, debug=debug, max_stalls=max_out_stalls) for bus_name in output_buses})

        self._forked_clock = None

    async def reset_dut(self, duration):
        self.reset <= self.reset_val
        await Timer(duration)
        self.reset <= ~(self.reset_val)
        await self.clock_edge
        self.log.debug("Reset complete")

    async def start(self):
        if not self.started:
            clock = Clock(self.clock, period=self.clock_period)
            self._forked_clock = cocotb.fork(clock.start())
            await cocotb.fork(self.reset_dut(2.5*self.clock_period))
            self.started = True

    async def launch_monitors(self):
        for mon in self.monitors.__dict__.values():
            await mon.fork()

    async def launch_drivers(self):
        for driver in self.drivers.__dict__.values():
            await driver.fork()

    async def join_monitors(self, timeout=None):
        for mon in self.monitors.__dict__.values():
            await mon.join(timeout)

    async def join_drivers(self, timeout=None):
        for driver in self.drivers.__dict__.values():
            await driver.join(timeout)


class LwcTb(Tb):
    def __init__(self, dut: SimHandleBase, debug=False, max_in_stalls=0, max_out_stalls=0) -> None:

        super().__init__(dut=dut,
                         input_buses=['pdi', 'sdi'], output_buses=['do'], debug=debug, max_in_stalls=max_in_stalls, max_out_stalls=max_out_stalls)

        self.pdi: ValidReadyDriver = self.drivers.pdi
        self.sdi: ValidReadyDriver = self.drivers.sdi
        self.do: ValidReadyMonitor = self.monitors.do

    def enqueue_message(self, instruction: Instruction, *segments: Segment):
        sender = self.sdi if instruction.op == OpCode.LDKEY else self.pdi
        width = sender.width

        # self.log.debug(f'enqueuing instruction {instruction} on {sender.name}')
        message = instruction.to_words(width)
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

            message.extend(segment.to_words(width))

        sender.queue.put(message)

    def expect_message(self, *segments: Segment, status=Status.Success):
        width = self.do.width
        message = []
        for segment in segments:
            exp_words = segment.to_words(width)
            message.extend(exp_words)
        message.extend(status.to_words(width))
        self.do.queue.put(message)

    async def encrypt_test(self, key, nonce, ad, pt, ct, tag):
        self.enqueue_message(Instruction(OpCode.ACTKEY))
        self.enqueue_message(Instruction(OpCode.LDKEY),
                             *Segment.segmentize(SegmentType.KEY, key))
        self.enqueue_message(Instruction(OpCode.ENC),
                             *Segment.segmentize(SegmentType.NPUB, nonce),
                             *Segment.segmentize(SegmentType.AD, ad),
                             *Segment.segmentize(SegmentType.PT, pt))
        # EOI is set to ‘0’ for output segments
        self.expect_message(
            *Segment.segmentize(SegmentType.CT, ct, last=0, eot=1, eoi=0),
            *Segment.segmentize(SegmentType.TAG, tag, last=1, eot=1, eoi=0)
        )

    async def decrypt_test(self, key, nonce, ad, pt, ct, tag):
        self.enqueue_message(Instruction(OpCode.ACTKEY))
        self.enqueue_message(Instruction(OpCode.LDKEY),
                             *Segment.segmentize(SegmentType.KEY, key))
        self.enqueue_message(Instruction(OpCode.DEC),
                             *Segment.segmentize(SegmentType.NPUB, nonce),
                             *Segment.segmentize(SegmentType.AD, ad),
                             *Segment.segmentize(SegmentType.CT, ct),
                             *Segment.segmentize(SegmentType.TAG, tag)
                             )
        self.expect_message(Segment(SegmentType.PT, pt, last=1, eot=1, eoi=0))

    async def hash_test(self, hm, digest):
        self.enqueue_message(Instruction(OpCode.HASH),
                             *Segment.segmentize(SegmentType.HM, hm)
                             )
        self.expect_message(
            *Segment.segmentize(SegmentType.DIGEST, digest, last=1, eot=1, eoi=0))



class LwcRefCheckerTb(LwcTb):
    def __init__(self, dut: SimHandleBase, ref: Union[LwcAead, LwcHash], debug, max_in_stalls, max_out_stalls) -> None:
        super().__init__(dut, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls)
        self.debug = debug
        
        self.ref = ref
        self.rand_inputs = not debug

    def gen_inputs(self, numbytes):
        s = 0 if numbytes > 1 else 1
        return rand_bytes(numbytes) if self.rand_inputs else bytes([i % 255 for i in range(s, numbytes+s)])

    async def xenc_test(self, ad_size, pt_size):
        key = self.gen_inputs(self.ref.CRYPTO_KEYBYTES)
        npub = self.gen_inputs(self.ref.CRYPTO_NPUBBYTES)
        ad = self.gen_inputs(ad_size)
        pt = self.gen_inputs(pt_size)
        tag, ct = self.ref.encrypt(pt, ad, npub, key)
        if self.debug:
            print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\n' +
                  f'pt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')
        await self.encrypt_test(key, npub, ad, pt, ct, tag)

    async def xdec_test(self, ad_size, ct_size):
        key = self.gen_inputs(self.ref.CRYPTO_KEYBYTES)
        npub = self.gen_inputs(self.ref.CRYPTO_NPUBBYTES)
        ad = self.gen_inputs(ad_size)
        pt = self.gen_inputs(ct_size)
        tag, ct = self.ref.encrypt(pt, ad, npub, key)
        if self.debug:
            print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\n' +
                  f'pt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')
        await self.decrypt_test(key, npub, ad, pt, ct, tag)

    async def xhash_test(self, hm_size):
        hm = self.gen_inputs(hm_size)
        digest = self.ref.hash(hm)
        await self.hash_test(hm, digest=digest)

    async def measure_op(self, op_dict: dict, timeout=None):
        t0 = get_sim_time()
        op = op_dict['op']
        ad_size = op_dict.get('ad_size')
        xt_size = op_dict.get('xt_size')
        hm_size = op_dict.get('hm_size')
        if op == 'enc':
            assert ad_size is not None and xt_size is not None
            await self.xenc_test(ad_size=ad_size, pt_size=xt_size)
        elif op == 'dec':
            assert ad_size is not None and xt_size is not None
            await self.xdec_test(ad_size=ad_size, ct_size=xt_size)
        elif op == 'hash':
            assert hm_size is not None
            await self.xhash_test(hm_size=hm_size)
        await self.launch_monitors()
        await self.launch_drivers()
        await self.join_drivers(timeout)
        await self.join_monitors(timeout)
        t1 = get_sim_time()
        cycles = (t1 - t0) // self.clock_period
        return cycles - 1 # consistent with VHDL TB

