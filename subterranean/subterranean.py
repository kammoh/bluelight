#!/usr/bin/env python3

from lwc_api import LwcAead, LwcHash, LwcCffi

from typing import Tuple
from pathlib import Path
from typing import Tuple
import os
import inspect
import random

SCRIPT_DIR = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))


class SubterraneanCref(LwcCffi, LwcAead, LwcHash):
    """ Python wrapper for C-Reference implementation """
    aead_algorithm = 'subterraneanv1'
    hash_algorithm = 'subterraneanv1'
    root_cref_dir = Path(SCRIPT_DIR) / 'cref'


# based on Python reference implementation by Subterranean team

SUBTERRANEAN_SIZE = 257

MultiplicativeSubgroup = [1] * 33
for i in range(32):
    MultiplicativeSubgroup[i+1] = 176 * \
        MultiplicativeSubgroup[i] % SUBTERRANEAN_SIZE


def chunks(lst, k):
    for i in range(0, len(lst), k):
        yield lst[i:i+k]


def bytearray_to_bits(value):
    if not value:
        return []
    value_bits = [((int(value[i//8]) & (1 << (i % 8))) >> (i % 8))
                  for i in range(len(value)*8)]
    return value_bits


def bits_to_bytearray(value):
    if value is None:
        return bytes(0)
    value_bytearray = bytearray((len(value)+7)//8)
    if len(value) != 0:
        if(len(value) % 8 == 0):
            final_position = len(value) - 8
        else:
            final_position = len(value) - (len(value) % 8)
        for i in range(0, final_position, 8):
            value_bytearray[i // 8] = value[i] + 2*value[i+1] + 4*value[i+2] + 8 * \
                value[i+3] + 16*value[i+4] + 32*value[i+5] + \
                64*value[i+6] + 128*value[i+7]
        mult_factor = 1
        last = final_position // 8
        value_bytearray[last] = 0
        for i in range(final_position, len(value)):
            value_bytearray[last] += mult_factor*value[i]
            mult_factor *= 2
    return value_bytearray

def bits_to_hex(bits):
    return bytes(reversed(bits_to_bytearray(bits))).hex()[1:]

class Subterranean(LwcAead, LwcHash):
    """ Subterranean 2.0 LWC """
    CRYPTO_KEYBYTES = 16
    CRYPTO_NPUBBYTES = 16
    CRYPTO_ABYTES = 16
    CRYPTO_HASH_BYTES = 32

    def __init__(self, debug=False) -> None:
        self.debug = debug
        self.initialize_state()

    def initialize_state(self) -> None:
        self.state = [0] * SUBTERRANEAN_SIZE

    def dump_state(self, msg=""):
        if self.debug:
            s = bits_to_hex(self.state)
            chunked = [s[0]] + list(chunks(s[1:], 8))
            print(
                f"{msg:22.22} {' '.join(chunked)}")

    def round(self):
        def chi(state):
            return [state[i] ^ ((1 ^ state[(i+1) % SUBTERRANEAN_SIZE]) & state[(i+2) % SUBTERRANEAN_SIZE]) for i in range(SUBTERRANEAN_SIZE)]

        def iota(state):
            return [1 ^ state[0]] + state[1:]

        def theta(state):
            return [state[i] ^ state[(i+3) % SUBTERRANEAN_SIZE] ^ state[(i+8) % SUBTERRANEAN_SIZE] for i in range(SUBTERRANEAN_SIZE)]

        def pi(state):
            return [state[(12*i) % SUBTERRANEAN_SIZE] for i in range(SUBTERRANEAN_SIZE)]

        self.state = pi(theta(iota(chi(self.state))))

    def duplex(self, sigma=[]):
        self.round()
        self.dump_state(f"after round")
        sigma1 = sigma + [1]
        if self.debug:
            print(f"adding {bits_to_hex(sigma1)}")
        for i in range(len(sigma1)):
            self.state[MultiplicativeSubgroup[i]] ^= sigma1[i]
        self.dump_state(f"after duplex ({len(sigma)} bits)")

    def extract(self):
        r = [self.state[j] ^ self.state[SUBTERRANEAN_SIZE-j] for i in range(32) for j in (MultiplicativeSubgroup[i],)]
        if self.debug:
            print(f"extraced {bits_to_hex(r)}")
        return r

    def absorb_unkeyed(self, value_in):
        for i in range(0, len(value_in), 8):
            self.duplex(value_in[i:i+8])
            self.duplex()
        # xof input is always byte aligned
        self.duplex()
        self.duplex()

    def absorb_keyed(self, value_in):
        for i in range(0, len(value_in), 32):
            self.duplex(value_in[i:i+32])
        if len(value_in) % 32 == 0:
            self.duplex()

    def absorb(self, value_in, decrypt: bool):
        value_out = []
        l = len(value_in)
        for i in range(0, l, 32):
            extracted = self.extract()
            out_chunk = [value_in[i+j] ^ extracted[j]
                              for j in range(min(32, l-i))]
            self.duplex(out_chunk if decrypt else value_in[i:i+32])
            value_out += out_chunk
        if l % 32 == 0:
            self.duplex()
        return value_out

    def blank(self, r_calls):
        for _ in range(r_calls):
            self.duplex()

    def squeeze(self, sz):
        Z = []
        for _ in range(sz // 32):
            Z += self.extract()
            self.duplex()
        return Z

    def xof_direct(self, message, sz):
        self.initialize_state()
        self.absorb_unkeyed(message)
        self.blank(8)
        return self.squeeze(sz)

    def sae_direct_crypt(self, key, nonce, ad, text, tag, tag_length, decrypt):
        self.initialize_state()
        self.absorb_keyed(key)
        self.dump_state("Key absorbed")
        self.absorb_keyed(nonce)
        self.dump_state("Nonce absorbed")
        self.blank(8)
        self.dump_state("8 blanks")
        self.absorb_keyed(ad)
        self.dump_state("AD absorbed")
        new_text = self.absorb(text, decrypt=decrypt)
        self.dump_state("message absorbed")
        self.blank(8)
        self.dump_state("8 blanks")
        new_tag = self.squeeze(tag_length)
        if decrypt:
            if tag != new_tag:
                return False, None
            return True, new_text
        return new_tag, new_text

    def crypt(self, text: bytes, ad: bytes, npub: bytes, key: bytes, tag: bytes, decrypt: bool):
        text_bits = bytearray_to_bits(text)
        ad_bits = bytearray_to_bits(ad)
        ad_bits = bytearray_to_bits(ad)
        npub_bits = bytearray_to_bits(npub)
        k_bits = bytearray_to_bits(key)
        t_prime_bits = bytearray_to_bits(tag)
        tv, text_bits = self.sae_direct_crypt(
            k_bits, npub_bits, ad_bits, text_bits, t_prime_bits, self.CRYPTO_ABYTES*8, decrypt)
        new_text = bits_to_bytearray(text_bits)
        if decrypt:
            return tv, new_text
        return bits_to_bytearray(tv), new_text

    def encrypt(self, pt: bytes, ad: bytes, npub: bytes, key: bytes) -> Tuple[bytes, bytes]:
        return self.crypt(text=pt, ad=ad, npub=npub, key=key, tag=None, decrypt=False)

    def decrypt(self, ct: bytes, ad: bytes, npub: bytes, key: bytes, tag: bytes) -> Tuple[bool, bytes]:
        return self.crypt(text=ct, ad=ad, npub=npub, key=key, tag=tag, decrypt=True)

    def hash(self, msg: bytes) -> bytes:
        m_bits = bytearray_to_bits(msg)
        hash_bits = self.xof_direct(m_bits, self.CRYPTO_HASH_BYTES*8)
        return bits_to_bytearray(hash_bits)


# def mylog(*args, **kwargs):
#     print(*args, **kwargs)


def rand_bytes(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))


def test_decrypt():
    cref = SubterraneanCref()
    pyref = Subterranean()
    print("testing decryption")
    for pt_len in range(0, 30):
        for ad_len in range(0, 30):
            # mylog(f'[D] pt_len={pt_len} ad_len={ad_len}')
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
            assert pt2 is not None
            assert cpt2 is not None
            assert cpt2 == pt, f"pt={pt.hex()} pt2={cpt2.hex()}"
            assert pt2 == pt, f"pt={pt.hex()} pt2={pt2.hex()}"


def test_hash():
    cref = SubterraneanCref()
    pyref = Subterranean()
    print("testing hash")
    for msg_len in range(0, 130):
        # mylog(f'[H] msg_len={msg_len}')
        msg = rand_bytes(msg_len)
        py_hash = pyref.hash(msg)
        c_hash = cref.hash(msg)
        # mylog(f'{py_hash.hex()}')
        assert py_hash == c_hash


def test_encrypt():
    print("here")
    cref = SubterraneanCref()
    pyref = Subterranean()
    print("testing encryption")
    for pt_len in range(0, 40):
        # mylog(f'pt_len={pt_len}')
        for ad_len in range(0, 40):
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


if __name__ == "__main__":
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    npub = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    pt = bytes.fromhex('0001')
    ad = bytes.fromhex('0001')

    cref = SubterraneanCref()
    pyref = Subterranean()
    pyref.debug = True
    tag, ct = pyref.encrypt(pt, ad, npub, key)
    c_tag, c_ct = cref.encrypt(pt, ad, npub, key)
    assert ct == c_ct, f"ct={ct.hex()} != c_ct={c_ct.hex()}"
    assert tag == c_tag, f"ct={tag.hex()} != c_ct={c_tag.hex()}"
    print(ct.hex().upper(), tag.hex().upper())

    pyref.debug = False
    # test_encrypt()
    test_decrypt()
    test_hash()
