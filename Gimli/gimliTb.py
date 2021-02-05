from pathlib import Path
import random
from random import randint
import sys
import os
import inspect
import itertools
from cocotb.handle import HierarchyObject
from functools import partial
from pprint import pprint

import cocotb

pprint = partial(pprint, sort_dicts=False)


SCRIPT_DIR = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

COCOLIGHT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.append(COCOLIGHT_DIR)
sys.path.append(SCRIPT_DIR)

# seed = random.randrange(sys.maxsize)
# random = random.Random(seed)
# print("Python random seed is:", seed)


try:
    from .cocolight.lwc_api import LwcCffi, LwcAead, LwcHash
    from .cocolight import LwcRefCheckerTb
except:
    from cocolight.lwc_api import LwcCffi, LwcAead, LwcHash
    from cocolight import LwcRefCheckerTb

XT_BS = 16
AD_BS = 16
HM_BS = 16


def short_sizes(bs):
    return [0, 1, 3, bs - 1, bs, bs + 1, 2 * bs - 1, 2 * bs, 2 * bs + 1]


class RefCheckerTb(LwcRefCheckerTb):
    def __init__(self, dut: HierarchyObject, debug=False, max_in_stalls=0, max_out_stalls=0, min_out_stalls=None) -> None:
        class Cref(LwcCffi, LwcAead, LwcHash):
            """ Python wrapper for C-Reference implementation """
            aead_algorithm = 'gimli24v1'
            hash_algorithm = 'gimli24v1'
            root_cref_dir = Path(SCRIPT_DIR) / 'cref'
        ref = Cref()
        super().__init__(dut, ref, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls, supports_hash=ref.hash_algorithm is not None)


@cocotb.test()
async def debug_enc(dut: HierarchyObject):
    debug = True
    max_in_stalls = 0
    min_out_stalls = 0
    max_out_stalls = 0
    tb = RefCheckerTb(dut, debug=debug, max_in_stalls=max_in_stalls,
                      max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls)

    await tb.start()

    await tb.xenc_test(ad_size=0,  pt_size=15)
    await tb.xenc_test(ad_size=0,  pt_size=4)
    await tb.xenc_test(ad_size=9,  pt_size=9)
    await tb.xenc_test(ad_size=4,  pt_size=24)
    await tb.xenc_test(ad_size=3,  pt_size=2)
    await tb.xenc_test(ad_size=0,  pt_size=2)
    await tb.xenc_test(ad_size=0,  pt_size=0)
    await tb.xenc_test(ad_size=0, pt_size=16)
    await tb.xenc_test(ad_size=44, pt_size=32)
    await tb.xenc_test(ad_size=45, pt_size=0)
    await tb.xenc_test(ad_size=44, pt_size=0)
    await tb.xenc_test(ad_size=0,  pt_size=45)
    await tb.xenc_test(ad_size=65, pt_size=65)
    await tb.xenc_test(ad_size=AD_BS + 1, pt_size=2*XT_BS + 1)
    await tb.xenc_test(ad_size=0, pt_size=XT_BS + 1)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers(20000)
    await tb.join_monitors(20000)


@cocotb.test()
async def debug_dec(dut: HierarchyObject):
    debug = True
    max_stalls = 10
    tb = RefCheckerTb(dut, debug=debug, max_in_stalls=max_stalls,
                      max_out_stalls=max_stalls)

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
async def debug_hash(dut: HierarchyObject):
    debug = True
    max_stalls = 0

    tb = RefCheckerTb(dut, debug=debug, max_in_stalls=max_stalls,
                      max_out_stalls=max_stalls)

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
async def blanket_test_simple(dut: HierarchyObject):
    debug = os.environ.get('DEBUG', False)
    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'DEBUG={debug}')

    max_in_stalls = 2
    max_out_stalls = 12
    min_out_stalls = None

    tb = RefCheckerTb(dut, debug=debug, max_in_stalls=max_in_stalls,
                      max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls)

    await tb.start()

    for ad_size, xt_size in itertools.product(short_sizes(AD_BS), short_sizes(XT_BS)):
        await tb.xdec_test(ad_size=ad_size, ct_size=xt_size)
        await tb.xenc_test(ad_size=ad_size, pt_size=xt_size)
        await tb.xhash_test(xt_size)

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
async def randomized_tests(dut: HierarchyObject):

    supports_hash = True

    debug = os.environ.get('DEBUG', False)
    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)
    print(f'DEBUG={debug}')

    tb = RefCheckerTb(dut, debug=debug, max_in_stalls=5, max_out_stalls=5)

    ad_sizes = [0, 1, 15, 16, 17,  23, 24, 25, 31, 32, 33, 43, 44, 45, 47, 48, 49, 61, 64, 65, 67, 3*AD_BS - 1 ] + \
        [randint(2, 500) for _ in range(30)] + short_sizes(AD_BS)

    ad_sizes = list(set(ad_sizes))  # unique
    random.shuffle(ad_sizes)
    xt_sizes = ad_sizes[:] + short_sizes(XT_BS)
    random.shuffle(xt_sizes)

    await tb.start()

    for ad_size, xt_size in itertools.product(ad_sizes, xt_sizes):
        op = randint(0, 2 if supports_hash else 1)
        if (op == 0):
            await tb.xenc_test(ad_size=ad_size, pt_size=xt_size)
        elif (op == 1):
            await tb.xdec_test(ad_size=ad_size, ct_size=xt_size)
        else:
            await tb.xhash_test(hm_size=xt_size)

    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()


@cocotb.test()
async def measure_timings(dut: HierarchyObject, supportsHash=False):

    debug = False

    max_stalls = 0  # for timing measurements

    tb = RefCheckerTb(
        dut, debug=debug, max_in_stalls=max_stalls, max_out_stalls=max_stalls)

    await tb.start()

    all_results = {}
    block_sizes = {'AD': AD_BS, 'PT/CT': XT_BS, 'HM':  HM_BS}

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
