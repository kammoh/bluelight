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

# seed = random.randrange(sys.maxsize)
# random = random.Random(seed)
# print("Python random seed is:", seed)

try:
    from .subterranean import Subterranean, SubterraneanCref
except:
    if script_dir not in sys.path:
        sys.path.append(script_dir)
    from subterranean import Subterranean, SubterraneanCref

try:
    from .cocolight import *
except:
    cocolight_dir = os.path.dirname(script_dir)
    if cocolight_dir not in sys.path:
        sys.path.append(cocolight_dir)
    from cocolight import *


class SubterraneanRefCheckerTb(LwcRefCheckerTb):
    def __init__(self, dut: SimHandleBase, debug, max_in_stalls, max_out_stalls, min_out_stalls=None, supports_hash=True) -> None:
        # ref = Subterranean(debug)
        ref = SubterraneanCref()
        super().__init__(dut, ref, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls, supports_hash=supports_hash)


@cocotb.test()
async def blanket_test_simple(dut: SimHandleBase):
    debug = os.environ.get('SUBTERRANEAN_DEBUG', False)
    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'SUBTERRANEAN_DEBUG={debug}')

    max_in_stalls = 2
    max_out_stalls = 12
    min_out_stalls = None

    tb = LwcRefCheckerTb(
        dut,
        ref=SubterraneanCref(),
        debug=debug, max_in_stalls=max_in_stalls, max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls, supports_hash=False)

    short_size = [0, 1, 15, 16, 43, 61, 64, 179] + [randint(2, 180) for _ in range(20)]

    # adsizes = [0, 1, 15, 10]
    # xtsizes = [0, 15]

    await tb.start()

    for ad_size, xt_size in itertools.product(short_size, short_size):
        await tb.xdec_test(ad_size=ad_size, ct_size=xt_size)
        await tb.xenc_test(ad_size=ad_size, pt_size=xt_size)
        # await tb.xhash_test(xt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        await tb.xenc_test(ad_size=ad_size, pt_size=pt_size)

    for ad_size, pt_size in itertools.product(short_size, short_size):
        await tb.xdec_test(ad_size=ad_size, ct_size=pt_size)

    await tb.xdec_test(ad_size=1536, ct_size=0)
    await tb.xenc_test(ad_size=1536, pt_size=0)
    await tb.xdec_test(ad_size=0, ct_size=1536)
    await tb.xenc_test(ad_size=0, pt_size=1536)
    await tb.xdec_test(ad_size=0, ct_size=1535)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()


@cocotb.test()
async def randomized_tests(dut: SimHandleBase):

    supports_hash = False

    debug = os.environ.get('SUBTERRANEAN_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'SUBTERRANEAN_DEBUG={debug}')

    tb = SubterraneanRefCheckerTb(
        dut, debug=debug, max_in_stalls=5, max_out_stalls=5)

    sizes = [0, 1, 15, 16, 17,  23, 24, 25, 31, 32, 33, 43, 44, 45, 47, 48, 49, 61, 64, 65, 67] + \
        [randint(2, 500) for _ in range(30)]

    sizes = list(set(sizes))  # unique
    random.shuffle(sizes)
    sizes2 = sizes[:]
    random.shuffle(sizes2)

    await tb.start()

    for size1, size2 in itertools.product(sizes, sizes2):
        op = randint(0, 2 if supports_hash else 1)
        if (op == 0):
            await tb.xenc_test(ad_size=size1, pt_size=size2)
        elif (op == 1):
            await tb.xdec_test(ad_size=size1, ct_size=size2)
        else:
            await tb.xhash_test(hm_size=size1)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()


@cocotb.test()
async def debug_enc(dut: SimHandleBase):
    debug = True
    max_in_stalls = 0
    min_out_stalls = 1
    max_out_stalls = 10
    tb = LwcRefCheckerTb(
        dut, ref=Subterranean(debug=debug), debug=debug, max_in_stalls=max_in_stalls, max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls)

    await tb.start()

    await tb.xenc_test(ad_size=0,  pt_size=15)
    await tb.xenc_test(ad_size=9,  pt_size=9)
    await tb.xenc_test(ad_size=4,  pt_size=24)
    await tb.xenc_test(ad_size=3,  pt_size=2)
    await tb.xenc_test(ad_size=0,  pt_size=2)
    await tb.xenc_test(ad_size=0,  pt_size=0)
    await tb.xenc_test(ad_size=44, pt_size=32)
    await tb.xenc_test(ad_size=45, pt_size=0)
    await tb.xenc_test(ad_size=44, pt_size=0)
    await tb.xenc_test(ad_size=0,  pt_size=45)
    await tb.xenc_test(ad_size=65, pt_size=65)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(20000)
    await tb.join_monitors(20000)


@cocotb.test()
async def debug_dec(dut: SimHandleBase):
    debug = True
    max_stalls = 10
    tb = LwcRefCheckerTb(
        dut, ref=Subterranean(debug=debug), debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    await tb.xdec_test(ad_size=4, ct_size=4)
    await tb.xdec_test(ad_size=4, ct_size=0)
    await tb.xdec_test(ad_size=0, ct_size=4)
    await tb.xdec_test(ad_size=0, ct_size=0)
    await tb.xdec_test(ad_size=45, ct_size=0)
    await tb.xdec_test(ad_size=44, ct_size=0)
    await tb.xdec_test(ad_size=1, ct_size=3)
    await tb.xdec_test(ad_size=65, ct_size=65)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()


@cocotb.test()
async def debug_hash(dut: SimHandleBase):
    debug = True
    max_stalls = 0

    tb = LwcRefCheckerTb(
        dut, ref=Subterranean(debug), debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

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
async def measure_timings(dut: SimHandleBase, supportsHash=False):

    debug = os.environ.get('SUBTERRANEAN_DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'SUBTERRANEAN_DEBUG={debug}')

    max_stalls = 0  # for timing measurements

    tb = SubterraneanRefCheckerTb(
        dut, debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    all_results = {}
    block_sizes = {'AD': 32 // 8, 'PT/CT': 32 // 8, 'HM':  8 // 8}

    sizes = [16, 64, 1536]

    for op in ['enc', 'dec']:
        results = {}
        bt = 'AD'
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=sz, xt_size=0))
            results[f'{bt} {sz}'] = cycles
        for x in [4, 5]:
            cycles = await tb.measure_op(dict(op=op, ad_size=x*block_sizes[bt], xt_size=0))
            results[f'{bt} {x}BS'] = cycles
        results[f'{bt} Long'] = results[f'{bt} 5BS'] - results[f'{bt} 4BS']
        bt = 'PT/CT'
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=0, xt_size=sz))
            results[f'{bt} {sz}'] = cycles
        for x in [4, 5]:
            cycles = await tb.measure_op(dict(op=op, ad_size=0, xt_size=x*block_sizes[bt]))
            results[f'{bt} {x}BS'] = cycles
        results[f'{bt} Long'] = results[f'{bt} 5BS'] - results[f'{bt} 4BS']
        bt = 'AD+PT/CT'
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, ad_size=sz, xt_size=sz))
            # print(f'{op} PT={sz} AD=0: {cycles}')
            results[f'{bt} {sz}'] = cycles
        for x in [4, 5]:
            cycles = await tb.measure_op(dict(op=op, ad_size=x*block_sizes['AD'], xt_size=x*block_sizes['PT/CT']))
            # print(f'{op} PT={sz} AD=0: {cycles}')
            results[f'{bt} {x}BS'] = cycles
        results[f'{bt} Long'] = results[f'{bt} 5BS'] - results[f'{bt} 4BS']
        all_results[op] = results

    if supportsHash:
        results = {}
        op = 'hash'
        bt = 'HM'
        for sz in sizes:
            cycles = await tb.measure_op(dict(op=op, hm_size=sz))
            # print(f'hash HM={sz}: {cycles}')
            results[f'{bt} {sz}'] = cycles
        for x in [4, 5]:
            cycles = await tb.measure_op(dict(op=op, hm_size=x*block_sizes[bt]))
            results[f'{bt} {x}BS'] = cycles
        results[f'{bt} Long'] = results[f'{bt} 5BS'] - results[f'{bt} 4BS']
        all_results[op] = results

    pprint(all_results)


if __name__ == "__main__":
    print("should be run as a cocotb module")
