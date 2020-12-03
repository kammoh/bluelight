
from typing import Iterable, Tuple, Any, Optional, Callable
from cocotb.triggers import RisingEdge, ReadOnly, NextTimeStep, Edge
from cocotb.log import SimLog
from cocotb.handle import SimHandleBase


class ValidReadyDriver:
    def __init__(self, entity: SimHandleBase, name: str, clock: SimHandleBase, debug=False) -> None:
        self._valid = getattr(entity, f'{name}_valid')
        self._ready = getattr(entity, f'{name}_ready')
        self.name = name
        self.entity = entity
        self.clock = clock
        self._debug = debug
        self.clock_edge = RisingEdge(clock)
        self._valid.setimmediatevalue(0)

        self._data_sig = getattr(self.entity, f'{self.name}_data')
        self._wx = (len(self._data_sig) + 3) // 4

    async def __call__(self, data):
        # dut._id(f"{sig_name}", extended=False) ?
        if data:
            # if isinstance(data, dict):
            #     for sub, value in data.items():
            #         getattr(self.entity, f'{self.name}_{sub}') <= value
            # else:
            data = int(data) # handle str as well
            if self._debug:
                print(f'putting 0x{data:0{self._wx}x} on {self._data_sig.name}')
            self._data_sig <= data
        self._valid <= 1

        while True:
            await ReadOnly()
            if self._ready.value:
                break
            await self.clock_edge
        await self.clock_edge
        self._valid <= 0


class ValidReadyMonitor:
    def __init__(self, entity: SimHandleBase, name: str, clock: SimHandleBase, debug=False) -> None:
        self._valid = getattr(entity, f'{name}_valid')
        self._ready = getattr(entity, f'{name}_ready')
        self.name = name
        self.entity = entity
        self.clock = clock
        self.clock_edge = RisingEdge(clock)
        self._ready.setimmediatevalue(0)
        self._stop = False
        self._data_sig = getattr(self.entity, f'{self.name}_data')
        self._callback: Callable = None
        self._received_buffer = []
        self._expected = []
        self._debug = debug

    # TODO just single "data" field implemented
    async def __call__(self):
        self._ready <= 1

        self._received_buffer.clear()

        wx = (len(self._data_sig) + 3) // 4

        while not self._stop:
            await ReadOnly()
            # TODO add ready generator
            if self._valid.value:
                v = int(self._data_sig.value)
                if self._debug:
                    print(f'Received 0x{v:0{wx}x} from {self._data_sig.name}')
                self._received_buffer.append(v)
                if self._callback and self._expected and len(self._received_buffer) == len(self._expected):
                    self._callback(self._received_buffer, self._expected)
                    self._received_buffer.clear()
            await self.clock_edge
        await self.clock_edge
        self._ready <= 0
    
    def set_expect(self, expected_data, callback):
        self._expected = expected_data
        self._callback = callback

