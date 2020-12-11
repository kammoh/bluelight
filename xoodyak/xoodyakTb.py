import sys
import os
import inspect
import itertools

from cocotb.triggers import Join
from cocotb.handle import SimHandleBase
from cocotb.utils import get_sim_time


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


class XoodyakRefCheckerTb(LwcRefCheckerTb):
    def __init__(self, dut: SimHandleBase, debug, max_in_stalls, max_out_stalls) -> None:
        # ref = Xoodyak(debug)
        ref = XoodyakCref()
        super().__init__(dut, ref, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls)

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
        tb.xdec_test(ad_size=ad_size, ct_size=pt_size)
        tb.xhash_test(pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)

    for ad_size, pt_size in itertools.product(short_size, full_sizes):
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)
        tb.xdec_test(ad_size=ad_size, ct_size=pt_size)

    tb.xdec_test(ad_size=1536, ct_size=0)
    tb.xenc_test(ad_size=1536, pt_size=0)
    tb.xenc_test(ad_size=0, pt_size=1536)
    tb.xdec_test(ad_size=0, ct_size=1535)

    for i in full_sizes + list(range(1535, 1555)):
        tb.xhash_test(i)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xdec_test(ad_size=ad_size, ct_size=pt_size)
        tb.xenc_test(ad_size=ad_size, pt_size=pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        tb.xdec_test(ad_size=ad_size, ct_size=pt_size)

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

    max_stalls = 0 # for timing measurements

    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()
    block_size = 128 // 8
    for sz in [16, 64, 1536, 4 * block_size, 5 * block_size]:
        for op in ['enc', 'dec']:
            cycles = await tb.measure_op(dict(op=op, ad_size=0, xt_size=sz))
            print(f'{op} PT={sz} AD=0: {cycles}')
            cycles = await tb.measure_op(dict(op=op, ad_size=sz, xt_size=0))
            print(f'{op} PT={sz} AD=0: {cycles}')

        cycles = await tb.measure_op(dict(op='hash', hm_size=sz))
        print(f'hash HM={sz}: {cycles}')
        


    # d1 = await measure_op(dict(op='dec', ad_size=0, ct_size=1536))

    await tb.clock_edge

if __name__ == "__main__":
    print("should be run as a cocotb module")
