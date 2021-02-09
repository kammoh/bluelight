
from random import randint, random
from cocolight.utils import rand_bytes
from cocolight.lwc_api import LwcAead, LwcHash, LwcCffi
from cocolight.bluespec_interface import *
import inspect
import sys
import os
from pathlib import Path
import cocotb
from cocotb.clock import Clock
from cocotb.handle import HierarchyObject
from cocotb.triggers import ClockCycles, RisingEdge


SCRIPT_DIR = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

COCOLIGHT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.append(COCOLIGHT_DIR)
sys.path.append(SCRIPT_DIR)


try:
    from pyref import GimliPyRef
except:
    from .pyref import GimliPyRef


class Cref(LwcCffi, LwcAead, LwcHash):
    """ Python wrapper for C-Reference implementation """
    aead_algorithm = 'gimli24v1'
    hash_algorithm = 'gimli24v1'
    root_cref_dir = Path(SCRIPT_DIR) / 'cref'


class CipherTb:
    def __init__(self, dut) -> None:
        self.dut = dut
        self.log = dut._log
        block_bytes = 16
        self.blockUp = ActionMethod('blockUp', dut, dict(block=BsvBits(block_bytes*8), valids=BsvBits(block_bytes), key=BsvBool(
        ), ct=BsvBool(), ad=BsvBool(), npub=BsvBool(), hash=BsvBool(), first=BsvBool(), last=BsvBool()))
        self.blockDown = ActionMethod('blockDown', dut)
        self.clock = dut.clk
        self.reset = dut.rst
        self.clock_edge = RisingEdge(self.clock)

    async def start(self):
        clock = self.clock
        reset = self.reset
        self.blockUp.en <= 0
        self.blockDown.en <= 0
        cocotb.fork(Clock(clock, 10, 'ns').start())

        reset <= 1
        print("b4 await ")
        await ClockCycles(clock, 2)
        reset <= 0
        self.dut._log.info("reset done ")

    async def blockin(self, data: bytes, **kwargs):
        width = 128 // 8
        ld = len(data)
        rets = []
        for i in range(0, ld, width):
            block = data[i:i+width]
            last = (ld - i <= width)
            valids = (1 << (len(block) - last)) - 1
            r = await self.blockUp(block=block, valids=valids, first=(i == 0), last=last, **kwargs)
            rets.append(r)
        return rets


@cocotb.test()
async def test_enc(dut: HierarchyObject):
    ref = Cref()
    pyref = GimliPyRef()

    tb = CipherTb(dut)
    await tb.start()

    sizes = list(range(5)) + [15, 16, 17, 31, 32, 33] + \
        [randint(34, 129) for _ in range(11)]
    sizes = list(set(sizes))

    for pt_sz in sizes:
        for ad_sz in {0, pt_sz, randint(0, 67)}:
            key = rand_bytes(ref.CRYPTO_KEYBYTES)
            npub = rand_bytes(ref.CRYPTO_NPUBBYTES)
            ad = rand_bytes(ad_sz)
            pt = rand_bytes(pt_sz)
            ct, tag = ref.encrypt(pt=pt, ad=ad, npub=npub, key=key)
            ct1, tag1 = pyref.encrypt(pt=pt, ad=ad, npub=npub, key=key)
            assert ct1 == ct
            assert tag1 == tag
            print(f'ad={ad.hex()}\npt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}')

            print("sending key...")
            await tb.blockin(key, key=1)
            print("sending npub...")
            await tb.blockin(npub, npub=1)
            print("sending AD...")
            await tb.blockin(ad + b'\1', ad=1)
            print("sending PT...")
            r = await tb.blockin(pt + b'\1')

            out = vals2bytes(r)[:len(pt)]
            print(f" ct = {out.hex()}")
            assert out == ct

            r = await tb.blockDown()
            out = vals2bytes(r)
            print(f" out tag = {out.hex()}")
            assert tag == out

    await tb.clock_edge


@cocotb.test()
async def test_dec(dut: HierarchyObject):
    ref = Cref()
    pyref = GimliPyRef()

    tb = CipherTb(dut)
    await tb.start()

    sizes = list(set(
        list(range(5)) + [15, 16, 17, 31, 32, 33] +
        [randint(34, 129) for _ in range(20)]
    )
    )

    for sz in sizes:
        for ad_sz in {0, sz, randint(0, 67)}:
            key = rand_bytes(32)
            npub = rand_bytes(16)
            ad = rand_bytes(ad_sz)
            pt = rand_bytes(sz)
            ct, tag = ref.encrypt(pt=pt, ad=ad, npub=npub, key=key)
            ct1, tag1 = pyref.encrypt(pt=pt, ad=ad, npub=npub, key=key)
            assert ct1 == ct
            assert tag1 == tag
            print(f'ad={ad.hex()}\npt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}')

            print("sending key...")
            await tb.blockin(key, key=1)
            print("sending npub...")
            await tb.blockin(npub, npub=1)
            print("sending AD...")
            await tb.blockin(ad + b'\1', ad=1)
            print("sending CT...")
            r = await tb.blockin(ct + b'\1', ct=1)

            out = vals2bytes(r)[:len(ct)]
            print(f" pt = {out.hex()}")
            assert out == pt

            r = await tb.blockDown()
            out = vals2bytes(r)
            print(f" out tag = {out.hex()}")
            assert tag == out

    await tb.clock_edge


@cocotb.test()
async def test_hash(dut: HierarchyObject):
    ref = Cref()
    pyref = GimliPyRef()

    tb = CipherTb(dut)
    await tb.start()

    sizes = list(range(5)) + [7, 8, 9, 127] + \
        [randint(6, 200) for _ in range(22)]

    for sz in sizes:
        msg = rand_bytes(sz)
        digest = ref.hash(msg)
        py_digest = pyref.hash(msg)
        assert digest == py_digest
        print(f'msg={msg.hex()}\ndigest={digest.hex()}')

        print("sending hash message...")
        await tb.blockin(msg + b'\1', hash=1)

        r = [await tb.blockDown(), await tb.blockDown()]
        out = vals2bytes(r)
        print(f" out digest = {out.hex()}")
        assert digest == out

    await tb.clock_edge
