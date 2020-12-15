from random import randint
import sys
import os
import inspect
import itertools

from cocotb.handle import SimHandleBase


script_dir = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

try:
    from .pyxoodyak import Xoodyak
    from .pyxoodyak.xoodyak_cref import XoodyakCref
except:
    cocolight_dir = script_dir
    if cocolight_dir not in sys.path:
        sys.path.append(cocolight_dir)
    from pyxoodyak import Xoodyak
    from pyxoodyak.xoodyak_cref import XoodyakCref

try:
    from .cocolight import *
except:
    cocolight_dir = os.path.dirname(script_dir)
    if cocolight_dir not in sys.path:
        sys.path.append(cocolight_dir)
    from cocolight import *


class XoodyakRefCheckerTb(LwcRefCheckerTb):
    def __init__(self, dut: SimHandleBase, debug, max_in_stalls, max_out_stalls) -> None:
        # ref = Xoodyak(debug)
        ref = XoodyakCref()
        super().__init__(dut, ref, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls)

@cocotb.test()
async def blanket_test1(dut: SimHandleBase):

    debug = os.environ.get('XOODYAK_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=10, max_out_stalls=10)

    short_size = [0, 1, 15, 16, 43, 61, 64, 179] + [randint(2,180) for _ in range (20)]

    await tb.start()

    for ad_size, pt_size in itertools.product(short_size, short_size):
        await tb.xdec_test(ad_size=ad_size, ct_size=pt_size)
        await tb.xhash_test(pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        await tb.xenc_test(ad_size=ad_size, pt_size=pt_size)


    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()

@cocotb.test()
async def blanket_test2(dut: SimHandleBase):

    debug = os.environ.get('XOODYAK_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=5, max_out_stalls=5)


    sizes = [0, 1, 15, 16, 43, 61, 64, 179, 1536] + [randint(2,180) for _ in range (20)]

    await tb.start()

    await tb.xdec_test(ad_size=1536, ct_size=0)
    await tb.xenc_test(ad_size=1536, pt_size=0)
    await tb.xenc_test(ad_size=0, pt_size=1536)
    await tb.xdec_test(ad_size=0, ct_size=1535)



    for size1, size2 in itertools.product(sizes, sizes):
        op = randint(0, 2)
        if (op == 0):
            await tb.xenc_test(ad_size=size1, pt_size=size2)
        elif (op == 1):
            await tb.xdec_test(ad_size=size1, ct_size=size2)
        else:
            await tb.xhash_test(hm_size=size1)
            await tb.xhash_test(hm_size=size1 + size2)


    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()


@cocotb.test()
async def debug_enc(dut: SimHandleBase):

    # debug = os.environ.get('XOODYAK_DEBUG', False)
    debug = True

    # try:
    #     debug = bool(int(debug))
    # except:
    #     debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    max_stalls = 10
    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    await tb.xenc_test(ad_size=0, pt_size=64)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(10000)
    await tb.join_monitors(10000)

@cocotb.test()
async def debug_enc(dut: SimHandleBase):

    # debug = os.environ.get('XOODYAK_DEBUG', False)
    debug = True

    # try:
    #     debug = bool(int(debug))
    # except:
    #     debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    max_stalls = 0
    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    await tb.xdec_test(ad_size=45, ct_size=0)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(10000)
    await tb.join_monitors(10000)

@cocotb.test()
async def debug_hash(dut: SimHandleBase):
    debug = True
    max_stalls = 0

    tb = LwcRefCheckerTb(
        dut, ref=Xoodyak(debug), debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    await tb.xhash_test(15)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(10000)
    await tb.join_monitors(10000)


@cocotb.test()
async def test_timing(dut: SimHandleBase):

    debug = os.environ.get('XOODYAK_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'XOODYAK_DEBUG={debug}')

    max_stalls = 0  # for timing measurements

    tb = XoodyakRefCheckerTb(
        dut, debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    # PT/CT
    block_size = 128 // 8
    sizes = [16, 64, 1536, 4 * block_size, 5 * block_size]
    for op in ['enc', 'dec']:
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=0, xt_size=sz))
            print(f'{op} PT={sz} AD=0: {cycles}')

    # AD
    block_size = 192 // 8
    sizes = [16, 64, 1536, 4 * block_size, 5 * block_size]    
    for op in ['enc', 'dec']:
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=sz, xt_size=0))
            print(f'{op} PT=0 AD={sz}: {cycles}')

    block_size = 128 // 8
    sizes = [16, 64, 1536, 4 * block_size, 5 * block_size]

    for sz in sizes:
        cycles = await tb.measure_op(dict(op='hash', hm_size=sz))
        print(f'hash HM={sz}: {cycles}')


if __name__ == "__main__":
    print("should be run as a cocotb module")
