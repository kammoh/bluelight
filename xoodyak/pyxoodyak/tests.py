

# Testing: verify Python implementation against reference C implementation
#   compatible with pytest/pytest-xdist
## run with pytest-xdist with 8 parallel threads:
### pytest -n 8 xoodyak.py

import sys
import os
import inspect
import random

# SCRIPT_DIR = os.path.realpath(os.path.dirname(
#     inspect.getfile(inspect.currentframe())))
# sys.path.append(SCRIPT_DIR)

from . import Xoodyak
from .xoodyak_cref import XoodyakCref
from .utils import rand_bytes

def mylog(*args, **kwargs):
    print(*args, **kwargs)


def test_decrypt():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for pt_len in range(100, 120):
        for ad_len in range(0, 100):
            mylog(f'[D] pt_len={pt_len} ad_len={ad_len}')
            pt = rand_bytes(pt_len)
            ad = rand_bytes(ad_len)
            nonce = rand_bytes(pyref.CRYPTO_NPUBBYTES)
            key = rand_bytes(pyref.CRYPTO_KEYBYTES)
            ctag, cct = cref.encrypt(pt, ad, nonce, key)
            ptag, pct = pyref.encrypt(pt, ad, nonce, key)
            # mylog(ct.hex().upper())
            assert cct == pct
            assert ctag == ptag
            decrypt_success, pt2 = pyref.decrypt(pct, ad, nonce, key, ptag)
            cdecrypt_success, cpt2 = cref.decrypt(cct, ad, nonce, key, ctag)
            assert decrypt_success
            assert cdecrypt_success
            assert pt2
            assert cpt2
            assert cpt2 == pt, f"pt={pt.hex()} pt2={cpt2.hex()}"
            assert pt2 == pt, f"pt={pt.hex()} pt2={pt2.hex()}"
            # mylog(ct.hex().upper())


def test_hash():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for msg_len in range(0, 1000):
        # mylog(f'[H] msg_len={msg_len}')
        msg = rand_bytes(msg_len)
        py_hash = pyref.hash(msg)
        c_hash = cref.hash(msg)
        # mylog(f'{py_hash.hex()}')
        assert py_hash == c_hash


def test_encrypt_small():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for pt_len in range(0, 100):
        # mylog(f'pt_len={pt_len}')
        for ad_len in range(0, 100):
            pt = rand_bytes(pt_len)
            ad = rand_bytes(ad_len)
            nonce = rand_bytes(cref.CRYPTO_NPUBBYTES)
            key = rand_bytes(cref.CRYPTO_KEYBYTES)
            ctag, cct = cref.encrypt(pt, ad, nonce, key)
            ptag, pct = pyref.encrypt(pt, ad, nonce, key)
            assert cct == pct
            assert ctag == ptag
            success, pt2 = cref.decrypt(pct, ad, nonce, key, ptag)
            assert success
            # mylog(ct.hex().upper())
            assert pt2 == pt, f'pt2:{pt2} != pt:{pt}'


def test_decrypt_fail():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for ct_len in range(0, 100):
        for ad_len in range(0, 10):
            ct = rand_bytes(ct_len)
            ad = rand_bytes(ad_len)
            nonce = rand_bytes(cref.CRYPTO_NPUBBYTES)
            key = rand_bytes(cref.CRYPTO_KEYBYTES)
            tag = rand_bytes(cref.CRYPTO_ABYTES)
            success1, pt1 = cref.decrypt(ct, ad, nonce, key, tag)
            success2, pt2 = pyref.decrypt(ct, ad, nonce, key, tag)
            assert success1 == success2
            assert pt1 == pt2, f'pt1:{pt1} != pt2:{pt2}'
            assert not success1  # highly unlikely!


def run_typical_tests():
    test_decrypt()
    test_encrypt_small()
    test_decrypt_fail()
    test_hash()


if __name__ == "__main__":
    print("WARNING: use pytest-xdist to run test in parallel")
    run_typical_tests()
