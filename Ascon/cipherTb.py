
from random import randint, random
from cocolight.utils import rand_bytes
from cocolight.lwc_api import LwcAead, LwcCffi
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


class Cref(LwcCffi, LwcAead):
    """ Python wrapper for C-Reference implementation """

    def __init__(self, aead_algorithm, hash_algorithm=None, root_cref_dir=Path(SCRIPT_DIR) / 'cref') -> None:
        Cref.aead_algorithm = aead_algorithm
        Cref.hash_algorithm = hash_algorithm
        Cref.root_cref_dir = root_cref_dir
        LwcCffi.__init__(self, force_recompile=True)

ref = Cref(aead_algorithm='ascon128v12', hash_algorithm='asconhashv12')
block_bits = dict(AD=64, PT=64)


class CipherTb:
    def __init__(self, dut: HierarchyObject, flags_t: BsvType, block_bytes:int, pad_byte: int, pad_extra_block=True) -> None:
        self.dut = dut
        self.flags_t = flags_t
        self.log = dut._log
        self.block_bytes = block_bytes
        self.pad_byte = pad_byte
        self.pad_extra_block = pad_extra_block
        self.clock = dut.clk if hasattr(dut, 'clk') else dut.CLK
        self.clock_edge = RisingEdge(self.clock)
        self.blockUp = ActionMethod('blockUp', dut, dict(block=BsvBits(
            block_bytes*8), valids=BsvBits(block_bytes), flags=flags_t), self.clock_edge)
        self.blockDown = ActionMethod('blockDown', dut, {}, self.clock_edge)
        if hasattr(dut, 'rst'):
            self.reset = dut.rst
            self.reset_val = 1
        else:
            self.reset = dut.RST_N
            self.reset_val = 0

    async def start(self):
        clock = self.clock
        self.blockUp.en <= 0
        self.blockDown.en <= 0
        cocotb.fork(Clock(clock, 10, 'ns').start())

        self.reset <= self.reset_val
        await ClockCycles(clock, 2)
        self.reset <= (not self.reset_val)
        self.log.info("reset done ")

    async def blockin(self, data: bytes, pad: bool, **kwargs):
        width = self.block_bytes
        pad = self.pad_byte if pad else None
        if not self.pad_extra_block and len(data) != 0 and (len(data) % width == 0):
            pad = None
        if pad is not None:
            data += int.to_bytes(pad, 1, 'little')
        empty = False
        if len(data) == 0:
            data = bytes().zfill(width)
            empty = True
        ld = len(data)
        rets = []
        for i in range(0, ld, width):
            block = data[i:i+width]
            last = (ld - i <= width)
            valids = 0 if empty else (
                1 << (len(block) - (bool(pad) and last))) - 1
            flags = dict(first=(i == 0), last=last, **kwargs)
            r = await self.blockUp(block=block, valids=valids, flags=flags)
            rets.append(r)
        return rets


flags_t = BsvStruct(
    key=BsvBool(), npub=BsvBool(), ad=BsvBool(), ptct=BsvBool(), ct=BsvBool(), hash=BsvBool(), first=BsvBool(), last=BsvBool()
)

def get_bytes(n_bytes, rand=False):
    if rand:
        return rand_bytes(n_bytes)
    return bytes(range(n_bytes))

@cocotb.test()
async def debug_enc(dut: HierarchyObject):
    tb = CipherTb(dut, flags_t, block_bytes=8, pad_byte=0x80, pad_extra_block=True)
    await tb.start()

    rand = False

    key = get_bytes(ref.CRYPTO_KEYBYTES, rand)
    npub = get_bytes(ref.CRYPTO_NPUBBYTES, rand)
    ad = get_bytes(16, rand)
    pt = get_bytes(0, rand)
    ct, tag = ref.encrypt(pt=pt, ad=ad, npub=npub, key=key)

    print(f'ad={ad.hex()}\npt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}')

    print("sending key...")
    await tb.blockin(key, pad=False, key=1)
    print("sending npub...")
    await tb.blockin(npub, pad=False, npub=1, eoi=(len(ad) == 0 and len(pt) == 0))
    print("sending AD...")
    await tb.blockin(ad, pad=True, ad=1, eoi=(len(ad) != 0 and len(pt) == 0))
    print("sending PT...")
    r = await tb.blockin(pt, pad=True, ptct=1, eoi=(len(pt) != 0))

    out = vals2bytes(r)[:len(pt)]
    print(f" received CT: {out.hex()}")
    assert out == ct

    r = [await tb.blockDown(), await tb.blockDown()]
    out = vals2bytes(r)
    print(f" received tag: {out.hex()}")
    assert tag == out

    for _ in range(20):
        await tb.clock_edge


@cocotb.test()
async def debug_dec(dut: HierarchyObject):
    tb = CipherTb(dut, flags_t, block_bytes=8, pad_byte=0x80, pad_extra_block=True)
    await tb.start()

    rand = False

    key = get_bytes(ref.CRYPTO_KEYBYTES, rand)
    npub = get_bytes(ref.CRYPTO_NPUBBYTES, rand)
    ad = get_bytes(16, rand)
    pt = get_bytes(0, rand)
    ct, tag = ref.encrypt(pt=pt, ad=ad, npub=npub, key=key)

    print("\n\n decrypt:")
    pt2 = ref.decrypt(ct=ct, ad=ad, npub=npub, key=key, tag=tag)
    assert pt2 == pt

    print(f'ad={ad.hex()}\npt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}')
   
    print("sending key...")
    await tb.blockin(key, pad=False, key=1)
    print("sending npub...")
    await tb.blockin(npub, pad=False, npub=1, eoi=(len(ad) == 0 and len(pt) == 0))
    print("sending AD...")
    await tb.blockin(ad, pad=True, ad=1, eoi=(len(ad) != 0 and len(pt) == 0))
    print("sending CT...")
    r = await tb.blockin(ct, pad=True, ct=1, ptct=1, eoi=(len(ct) != 0))

    out = vals2bytes(r)[:len(ct)]
    print(f" received PT: {out.hex()}")
    assert out == pt

    r = [await tb.blockDown(), await tb.blockDown()]
    out = vals2bytes(r)
    print(f" received tag: {out.hex()}")
    assert tag == out

    for _ in range(1):
        await tb.clock_edge

@cocotb.test()
async def test_enc(dut: HierarchyObject):

    tb = CipherTb(dut, flags_t, block_bytes=8, pad_byte=0x80, pad_extra_block=True)
    await tb.start()

    ad_bs = block_bits['AD'] // 8
    pt_bs = block_bits['PT'] // 8

    sizes = [0, 1, pt_bs - 1, pt_bs, pt_bs + 1, 2*pt_bs - 1, 2 * pt_bs, 2*pt_bs + 1] + \
        [randint(2, 5*ad_bs) for _ in range(50)]
    sizes = list(set(sizes))

    for pt_sz in sizes:
        for ad_sz in {0, 1, pt_sz, ad_bs - 1, ad_bs, ad_bs + 1, 2*ad_bs - 1, 2 * ad_bs, 2 * ad_bs + 1, randint(2, 3 * ad_bs)}:
            key = rand_bytes(ref.CRYPTO_KEYBYTES)
            npub = rand_bytes(ref.CRYPTO_NPUBBYTES)
            ad = rand_bytes(ad_sz)
            pt = rand_bytes(pt_sz)
            ct, tag = ref.encrypt(pt=pt, ad=ad, npub=npub, key=key)

            print(
                f'key={key.hex()}   npub={npub.hex()}\nad={ad.hex()}\npt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}')

            print("sending key...")
            await tb.blockin(key, pad=False, key=1)
            print("sending npub...")
            await tb.blockin(npub, pad=False, npub=1, eoi=(len(ad) == 0 and len(pt) == 0))
            print("sending AD...")
            await tb.blockin(ad, pad=True, ad=1, eoi=(len(ad) != 0 and len(pt) == 0))
            print("sending PT...")
            r = await tb.blockin(pt, pad=True, ptct=1, eoi=(len(pt) != 0))

            out = vals2bytes(r)[:len(pt)]
            print(f" received ct: {out.hex()}")
            assert out == ct

            r = [await tb.blockDown(), await tb.blockDown()]
            out = vals2bytes(r)
            print(f" received tag: {out.hex()}")
            assert tag == out
            await tb.clock_edge


@cocotb.test()
async def test_dec(dut: HierarchyObject):

    tb = CipherTb(dut, flags_t, block_bytes=8, pad_byte=0x80, pad_extra_block=True)
    await tb.start()

    ad_bs = block_bits['AD'] // 8
    pt_bs = block_bits['PT'] // 8

    sizes = [0, 1, pt_bs - 1, pt_bs, pt_bs + 1, 2*pt_bs - 1, 2 * pt_bs, 2*pt_bs + 1] + \
        [randint(2, 5*ad_bs) for _ in range(50)]
    sizes = list(set(sizes))

    for pt_sz in sizes:
        for ad_sz in {0, 1, pt_sz, ad_bs - 1, ad_bs, ad_bs + 1, 2*ad_bs - 1, 2 * ad_bs, 2 * ad_bs + 1, randint(2, 3 * ad_bs)}:
            key = rand_bytes(ref.CRYPTO_KEYBYTES)
            npub = rand_bytes(ref.CRYPTO_NPUBBYTES)
            ad = rand_bytes(ad_sz)
            pt = rand_bytes(pt_sz)
            ct, tag = ref.encrypt(pt=pt, ad=ad, npub=npub, key=key)
            # pt2 = ref.decrypt(ct=ct, ad=ad, npub=npub, key=key, tag=tag)
            # assert pt2 == pt

            print(
                f'key={key.hex()} npub={npub.hex()}\nad={ad.hex()}\npt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}')

            print("sending key...")
            await tb.blockin(key, pad=False, key=1)
            print("sending npub...")
            await tb.blockin(npub, pad=False, npub=1, eoi=(len(ad) == 0 and len(pt) == 0))
            print("sending AD...")
            await tb.blockin(ad, pad=True, ad=1, eoi=(len(ad) != 0 and len(pt) == 0))
            print("sending CT...")
            r = await tb.blockin(ct, pad=True, ct=1, ptct=1, eoi=(len(ct) != 0))

            out = vals2bytes(r)[:len(ct)]
            print(f" received PT: {out.hex()}")
            assert out == pt

            r = [await tb.blockDown(), await tb.blockDown()]
            out = vals2bytes(r)
            print(f" received tag: {out.hex()}")
            assert tag == out

    await tb.clock_edge

# @cocotb.test()
# async def test_hash(dut: HierarchyObject):
#     ref = Cref()

#     tb = CipherTb(dut)
#     await tb.start()

#     sizes = list(range(5)) + [7, 8, 9, 127] + \
#         [randint(6, 200) for _ in range(22)]

#     for sz in sizes:
#         msg = rand_bytes(sz)
#         digest = ref.hash(msg)
#         print(f'msg={msg.hex()}\ndigest={digest.hex()}')

#         print("sending hash message...")
#         await tb.blockin(msg + b'\1', hash=1)

#         r = [await tb.blockDown(), await tb.blockDown()]
#         out = vals2bytes(r)
#         print(f" out digest = {out.hex()}")
#         assert digest == out

#     await tb.clock_edge
