import sys
import os
import inspect

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


@cocotb.test()
async def test_dut(dut: SimHandleBase):
    debug = os.environ.get('XOODYAK_DEBUG', False)

    # debug = True

    try:
        debug = bool(int(debug))
    except:
        debug = bool(debug)

    print(f'XOODYAK_DEBUG={debug}')
    # ref = Xoodyak(debug=debug)
    ref = XoodyakCref()

    tb = LwcTb(dut, debug=debug, max_in_stalls=3, max_out_stalls=5)

    # key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    # key =   bytes.fromhex('8763857D9B8CD0F96C3A6C119C3A8BFD')
    # npub = bytes.fromhex('6FC9B4E2F3644E8457F148974F81A049')

    # ad = bytes(0)
    # pt = bytes(0)
    # key = rand_bytes(16) # 128 bits
    # nonce = rand_bytes(16) # always 128 bits
    # ad = bytes.fromhex('20567811')
    # pt = rand_bytes(64)

    # tag, ct = ref.encrypt(pt, ad, npub, key)
    # print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\npt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')
    # tb.encrypt_test(key, npub, ad, pt, ct, tag)

    full_sizes = list(range(0, 43)) + \
        [0, 3, 48, 49, 59, 60, 61, 63, 64, 1535, 1536, 1537]

    short_size = [0, 1,  15, 16, 43, 44, 63, 64]
    quick_size = list(range(0, 18)) + [43, 44, 45, 63, 64, 65, 1536, 1537]

    single = [3]

    sizes = full_sizes  # quick_size
    rand_inputs = True  # True

    # if debug:
    #     sizes = single #short_size
    #     rand_inputs = False

    def gen_inputs(numbytes):
        s = 0 if numbytes > 1 else 1
        return rand_bytes(numbytes) if rand_inputs else bytes([i % 255 for i in range(s, numbytes+s)])
    await tb.start()

    def enc_tests():
        for pt_size in sizes:
            print(f'pt_size={pt_size}')
            for ad_size in sizes:

                key = gen_inputs(ref.CRYPTO_KEYBYTES)
                npub = gen_inputs(ref.CRYPTO_NPUBBYTES)  # always 128 bits
                ad = gen_inputs(ad_size)
                pt = gen_inputs(pt_size)

                tag, ct = ref.encrypt(pt, ad, npub, key)

                if debug:
                    print(
                        f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\npt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')

                tb.encrypt_test(key, npub, ad, pt, ct, tag)

    def dec_tests():
        for pt_size in sizes:
            print(f'pt_size={pt_size}')
            for ad_size in sizes:

                key = gen_inputs(ref.CRYPTO_KEYBYTES)
                npub = gen_inputs(ref.CRYPTO_NPUBBYTES)  # always 128 bits
                ad = gen_inputs(ad_size)
                pt = gen_inputs(pt_size)

                tag, ct = ref.encrypt(pt, ad, npub, key)

                if debug:
                    print(
                        f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\npt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')

                tb.decrypt_test(key, npub, ad, pt, ct, tag)

    enc_tests()
    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()
    print("encrypt tests done")

    dec_tests()
    await tb.launch_monitors()
    await tb.launch_drivers()

    await tb.join_drivers()
    await tb.join_monitors()
    print("decrypt tests done")

    # await Timer(2000)

    await tb.clkedge


if __name__ == "__main__":
    print("should be run as a cocotb module")
