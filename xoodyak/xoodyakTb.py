import random
from random import randint
import sys
import os
import inspect
import itertools
from cocotb.handle import SimHandleBase
from functools import partial
from pprint import pprint
pprint = partial(pprint, sort_dicts=False)


script_dir = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

seed = random.randrange(sys.maxsize)
random = random.Random(seed)
print("Python random seed is:", seed)

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


    await tb.xdec_test(ad_size=1536, ct_size=0)
    await tb.xenc_test(ad_size=1536, pt_size=0)
    await tb.xenc_test(ad_size=0, pt_size=1536)
    await tb.xdec_test(ad_size=0, ct_size=1535)

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


    sizes = [0, 1, 15, 16, 43, 61, 64, 179, 1536] + [randint(2,230) for _ in range (30)]

    sizes = list(set(sizes))
    random.shuffle(sizes)

    await tb.start()



    for size1, size2 in itertools.product(sizes, sizes):
        op = randint(0, 2)
        if (op == 0):
            # print("testing Encrypt")
            await tb.xenc_test(ad_size=size1, pt_size=size2)
        elif (op == 1):
            # print("testing Decrypt")
            await tb.xdec_test(ad_size=size1, ct_size=size2)
        else:
            # print("testing Hash x2")
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

    await tb.xenc_test(ad_size=63, pt_size=0)
    await tb.xenc_test(ad_size=0, pt_size=63)
    await tb.xenc_test(ad_size=44, pt_size=32)
    await tb.xenc_test(ad_size=65, pt_size=65)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(10000)
    await tb.join_monitors(10000)

@cocotb.test()
async def debug_dec(dut: SimHandleBase):

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
    await tb.xdec_test(ad_size=44, ct_size=0)
    await tb.xdec_test(ad_size=0, ct_size=45)
    await tb.xdec_test(ad_size=65, ct_size=65)

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

    # await tb.xhash_test(15)
    # await tb.xhash_test(16)
    await tb.xhash_test(32)
    # await tb.xhash_test(99)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(10000)
    await tb.join_monitors(10000)


@cocotb.test()
async def measure_timings(dut: SimHandleBase):

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

    all_results = {}
    block_sizes = {'AD': 352 // 8, 'PT/CT': 192 // 8, 'HM':  128 // 8}

    for op in ['enc', 'dec']:
        results = {}
        bt = 'AD'
        sizes = [16, 64, 1536, 4 * block_sizes[bt], 5 * block_sizes[bt]]    
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=sz, xt_size=0))
            # print(f'{op} PT=0 AD={sz}: {cycles}')
            results[f'{bt} {sz}'] = cycles

        bt = 'PT/CT'
        sizes = [16, 64, 1536, 4 * block_sizes[bt], 5 * block_sizes[bt]]
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=0, xt_size=sz))
            # print(f'{op} PT={sz} AD=0: {cycles}')
            results[f'{bt} {sz}'] = cycles

        bt = 'AD+PT/CT'
        sizes = [16, 64, 1536]
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=sz, xt_size=sz))
            # print(f'{op} PT={sz} AD=0: {cycles}')
            results[f'{bt} {sz}'] = cycles
        for x in [4,5]:
            cycles = await tb.measure_op(dict(op=op, ad_size=x*block_sizes['AD'], xt_size=x*block_sizes['PT/CT']))
            # print(f'{op} PT={sz} AD=0: {cycles}')
            results[f'{bt} {x}BS'] = cycles

        all_results[op] = results

    bt = 'HM'
    sizes = [16, 64, 1536, 4 * block_sizes[bt], 5 * block_sizes[bt]]
    results = {}
    for sz in sizes:
        cycles = await tb.measure_op(dict(op='hash', hm_size=sz))
        # print(f'hash HM={sz}: {cycles}')
        results[f'{bt} {sz}'] = cycles

    all_results['hash'] = results

    pprint(all_results)


if __name__ == "__main__":
    print("should be run as a cocotb module")
