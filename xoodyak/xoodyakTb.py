import sys
import os
import inspect
import itertools

from cocotb.triggers import Join
from cocotb.handle import SimHandleBase


script_dir = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

try:
    from .pyxoodyak import Xoodyak
    from .pyxoodyak.xoodyak_cref import XoodyakCref
    from .pyxoodyak.utils import rand_bytes
except:
    sys.path.insert(0, script_dir)
    from pyxoodyak import Xoodyak
    from pyxoodyak.xoodyak_cref import XoodyakCref
    from pyxoodyak.utils import rand_bytes

try:
    from .cocolight import *
except:
    cocolight_dir = os.path.dirname(script_dir)
    sys.path.insert(0, cocolight_dir)
    from cocolight import *


class XoodyakRefCheckerTb(LwcTb):
    def __init__(self, dut: SimHandleBase, debug, max_in_stalls, max_out_stalls) -> None:
        super().__init__(dut, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls)
        self.debug = debug

        # ref = Xoodyak(debug=debug)
        self.ref = XoodyakCref()
        self.rand_inputs = not debug

    def gen_inputs(self, numbytes):
        s = 0 if numbytes > 1 else 1
        return rand_bytes(numbytes) if self.rand_inputs else bytes([i % 255 for i in range(s, numbytes+s)])

    def xenc_test(self, ad_size, pt_size):
        key = self.gen_inputs(self.ref.CRYPTO_KEYBYTES)
        npub = self.gen_inputs(self.ref.CRYPTO_NPUBBYTES)
        ad = self.gen_inputs(ad_size)
        pt = self.gen_inputs(pt_size)
        tag, ct = self.ref.encrypt(pt, ad, npub, key)
        if self.debug:
            print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\n' +
                  f'pt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')
        self.encrypt_test(key, npub, ad, pt, ct, tag)

    def xdec_test(self, ad_size, pt_size):
        key = self.gen_inputs(self.ref.CRYPTO_KEYBYTES)
        npub = self.gen_inputs(self.ref.CRYPTO_NPUBBYTES)
        ad = self.gen_inputs(ad_size)
        pt = self.gen_inputs(pt_size)
        tag, ct = self.ref.encrypt(pt, ad, npub, key)
        if self.debug:
            print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\n' +
                  f'pt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')
        self.decrypt_test(key, npub, ad, pt, ct, tag)

    def xhash_test(self, hm_size):
        hm = self.gen_inputs(hm_size)
        digest = self.ref.hash(hm)
        self.hash_test(hm, digest=digest)


@cocotb.test()
async def test_dut(dut: SimHandleBase):

    debug = os.environ.get('XOODYAK_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=5, max_out_stalls=5)

    full_sizes = list(range(0, 43)) + \
        [61, 63, 64, 123, 127, 128, 777, 1535, 1536, 1537]

    short_size = [0, 1, 15, 16, 43, 61, 64, 179]
    quick_size = list(range(0, 18)) + [43, 44, 45, 63, 64, 65, 1536, 1537]

    await tb.start()

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xdec_test(ad_size=ad_size, pt_size=pt_size)
        tb.xhash_test(pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)

    for ad_size, pt_size in itertools.product(short_size, full_sizes):
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)
        tb.xdec_test(ad_size=ad_size, pt_size=pt_size)

    tb.xdec_test(ad_size=1536, pt_size=0)
    tb.xenc_test(ad_size=1536, pt_size=0)
    tb.xenc_test(ad_size=0, pt_size=1536)
    tb.xdec_test(ad_size=0, pt_size=1535)

    for i in full_sizes + list(range(1535, 1555)):
        tb.xhash_test(i)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xdec_test(ad_size=ad_size, pt_size=pt_size)
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xdec_test(ad_size=ad_size, pt_size=pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()

    await tb.clock_edge


@cocotb.test()
async def test_timing(dut: SimHandleBase):

    debug = os.environ.get('XOODYAK_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=5, max_out_stalls=5)

    await tb.start()

    # tb.xhash_test(5 * 128 // 8)
    tb.xenc_test(ad_size=0, pt_size=64)

    await tb.launch_monitors()
    await tb.launch_drivers()

    timeout=1000
    await tb.join_drivers(timeout)
    await tb.join_monitors(timeout)

    # await Timer(2000)

    await tb.clock_edge

if __name__ == "__main__":
    print("should be run as a cocotb module")
