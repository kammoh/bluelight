import random
from logging import Logger
from math import ceil
from queue import Queue
from types import SimpleNamespace
from typing import List

import cocotb
from cocotb.clock import Clock
from cocotb.handle import SimHandleBase
from cocotb.result import TestError, TestFailure
from cocotb.triggers import First, Join, ReadOnly, RisingEdge, Timer


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]

class ForkJoinBase:
    def __init__(self, dut: SimHandleBase, name: str) -> None:
        self._forked = None
        self.dut = dut
        self.name: str = name
        self.log: Logger = dut._log

    def run(self):
        pass

    async def fork(self) -> None:
        self._forked = cocotb.fork(self.run())
        self.log.debug(f"forked {self.name}")

    async def join(self, timeout=None) -> None:
        if self._forked is not None:
            if timeout:
                timer = Timer(timeout)
                first = await First(timer, self._forked)
                if first is timer:
                    self.log.error(
                        f"Joining {self.name} timed out! (timeout={timeout})")
                    raise TestFailure(f"timeout")
            else:
                await Join(self._forked)
            self.log.debug(f"joined {self.name}")
            self._forked = None
        else:
            self.log.error(
                f"{self.name} joined without being previously forked!")


class ValidReadyDriver(ForkJoinBase):
    def __init__(self, dut: SimHandleBase, name: str, clock: SimHandleBase, debug=False, min_stalls=0, max_stalls=0) -> None:
        super().__init__(dut, name)
        self._valid = getattr(dut, f'{name}_valid')
        self._ready = getattr(dut, f'{name}_ready')
        self.clock = clock
        self._debug = debug
        self.clock_edge = RisingEdge(clock)
        self.queue: Queue[List[int]] = Queue()
        self.max_stalls = max_stalls
        self.min_stalls = max_stalls
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
                r = random.randint(self.min_stalls, self.max_stalls)
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
    def __init__(self, dut: SimHandleBase, name: str, clock: SimHandleBase, debug=False, max_stalls=0, min_stalls=None) -> None:
        super().__init__(dut, name)
        self._valid = getattr(dut, f'{name}_valid')
        self._ready = getattr(dut, f'{name}_ready')
        self.clock = clock
        self.clock_edge = RisingEdge(clock)
        self._data_signal = getattr(self.dut, f'{self.name}_data')
        self.width = len(self._data_signal)
        self.failures = 0
        self.num_received_words = 0
        self._debug = debug
        self.queue: Queue[List[int]] = Queue()
        self.max_stalls = max_stalls
        self.min_stalls = min_stalls if min_stalls is not None else -self.max_stalls
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
            self.log.info(
                f"Verifying message #{num_verified_messages} ({len(message)} words) on '{self.name}'")
            for exp in message:
                # TODO add custom ready generator
                r = random.randint(self.min_stalls, self.max_stalls)
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


class ValidReadyTester:
    def __init__(self, dut: SimHandleBase, input_buses: List[str], output_buses: List[str], clock_name='clock', reset_name='reset', reset_val=1, debug=False, clk_period=10, min_in_stalls=0, max_in_stalls=0, max_out_stalls=0, min_out_stalls=0) -> None:
        self.dut = dut
        self.log = dut._log
        self.started = False
        self.reset = getattr(dut, reset_name)
        self.reset_val = reset_val

        self.clock = getattr(dut, clock_name)
        self.clock_period = clk_period
        self.clock_edge = RisingEdge(self.clock)
        self.drivers = SimpleNamespace(
            **{k: ValidReadyDriver(dut, k, self.clock, debug=debug, min_stalls=min_in_stalls, max_stalls=max_in_stalls) for k in input_buses})
        self.monitors = SimpleNamespace(**{bus_name: ValidReadyMonitor(
            dut=dut, name=bus_name, clock=self.clock, debug=debug, min_stalls=min_out_stalls, max_stalls=max_out_stalls) for bus_name in output_buses})

        self._forked_clock = None

    async def reset_dut(self, duration):
        print(f"asserting ")
        self.reset <= self.reset_val
        self.log.info(f"asserting reset to {self.reset_val} for {duration} time units.")
        await Timer(duration)
        self.log.info(f"de-asserting reset")
        self.reset <= (not self.reset_val)
        await self.clock_edge
        self.log.debug("Reset complete")

    async def start(self):
        if not self.started:
            self.log.info("starting clock...")
            clock = Clock(self.clock, period=self.clock_period)
            self._forked_clock = cocotb.fork(clock.start())
            self.log.info("reseting...")
            await cocotb.fork(self.reset_dut(2.5*self.clock_period))
            self.log.info("reset DONE")
            self.started = True
