# Xoodyak Lightweight AEAD and Hash and verification against reference C code
# Xoodyak, Cyclist, and XoodyakCref implementation by Kamyar Mohajerani <kamyar@ieee.org>
#
# Xoodoo implementation is based on Python code by Seth Hoffert,
#  available from https://github.com/KeccakTeam/Xoodoo/blob/master/Reference/Python/Xoodoo.py
#  modified by Kamyar Mohajerani
# 
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/

import sys
import random
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Tuple, Union
from cffi import FFI

VERBOSE_LEVEL = 1

class LwcCffi():
    @staticmethod
    def build_cffi(root_cref_dir, cand_name):
        headers = {
            'hash':
            '''
        int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long hlen);
        ''', 'aead': '''
        int crypto_aead_encrypt(
            unsigned char *c, unsigned long long *clen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *ad, unsigned long long adlen,
            const unsigned char *nsec,
            const unsigned char *npub,
            const unsigned char *k
        );
        int crypto_aead_decrypt(
            unsigned char *m, unsigned long long *mlen,
            unsigned char *nsec,
            const unsigned char *c,unsigned long long clen,
            const unsigned char *ad,unsigned long long adlen,
            const unsigned char *npub,
            const unsigned char *k
            );
        '''
        }

        for op, header in headers.items():
            ffibuilder = FFI()
            cref_dir = root_cref_dir / f'crypto_{op}' / cand_name / 'ref'
            hdr_file = cref_dir / f"crypto_{op}.h"
            if not hdr_file.exists():
                with open(hdr_file, 'w') as f:
                    f.write(header)
            api_h = cref_dir / f"api.h"
            if api_h.exists():
                with open(api_h) as f:
                    header += '\n' + f.read()

            ffibuilder.cdef(header)
            define_macros = []
            if VERBOSE_LEVEL is not None:
                define_macros.append(('VERBOSE_LEVEL', VERBOSE_LEVEL))
            ffibuilder.set_source(f"_{cand_name}_{op}",
                                  header,
                                  libraries=[],
                                  sources=[str(s) for s in cref_dir.glob("*.c")],
                                  include_dirs=[cref_dir],
                                  define_macros=define_macros
                                  )
            ffibuilder.compile(tmpdir='.', verbose=1, target=None, debug=None)


NROWS = 3
NCOLUMNS = 4
NLANES = NCOLUMNS*NROWS
LANE_BYTES = 4
STATE_BYTES = LANE_BYTES * NLANES

Xoodyak_f_bPrime = 48
Xoodyak_Rhash = 16
Xoodyak_Rkin = 44
Xoodyak_Rkout = 24

# API
CRYPTO_KEYBYTES = 16
CRYPTO_NPUBBYTES = 16
CRYPTO_HASH_BYTES = 32
TAGLEN = 16


class Plane:
    def __init__(self, lanes=None):
        if lanes is None:
            lanes = [0] * NCOLUMNS
        self.lanes = lanes

    def __getitem__(self, i):
        return self.lanes[i]

    def __setitem__(self, i, v):
        self.lanes[i] = v

    def __str__(self):
        return ' '.join(f"{x:08x}" for x in self.lanes)

    def __xor__(self, other: 'Plane') -> 'Plane':
        return Plane([self.lanes[x] ^ other.lanes[x] for x in range(4)])

    def __and__(self, other: 'Plane') -> 'Plane':
        return Plane([self.lanes[x] & other.lanes[x] for x in range(4)])

    def __invert__(self) -> 'Plane':
        return Plane([~self.lanes[x] for x in range(NCOLUMNS)])

    def cyclic_shift(self, dx, dz) -> 'Plane':
        def cyclic_shift_lane(lane, dz):
            if dz == 0:
                return lane
            return ((lane >> (32 - dz)) | (lane << dz)) % (1 << 32)
        return Plane([cyclic_shift_lane(self.lanes[(i - dx) % NCOLUMNS], dz) for i in range(NCOLUMNS)])


class State:
    ENDIAN = sys.byteorder

    def __init__(self):
        self.planes = [Plane() for _ in range(NROWS)]

    def __getitem__(self, i):
        return self.planes[i]

    def __setitem__(self, i, v):
        self.planes[i] = v

    def __str__(self):
        return ' - '.join(str(x) for x in self.planes)

    def set_zero(self):
        for i in range(NROWS):
            for j in range(NCOLUMNS):
                self.planes[i][j] = 0

    @staticmethod
    def _row_cols(i):
        plane_bytes = LANE_BYTES * NCOLUMNS
        assert i < plane_bytes * NROWS
        row = i // plane_bytes
        col = (i % plane_bytes) // LANE_BYTES
        return row, col

    @staticmethod
    def _linear_to_rco(i):
        """convert linear byte address to (row, column, offset)"""
        row, col = State._row_cols(i)
        offset = i % LANE_BYTES
        assert row < NROWS and col < NCOLUMNS
        return row, col, offset

    def get_byte(self, i):
        row, col, offset = State._linear_to_rco(i)
        lane = self.planes[row][col]
        return lane.to_bytes(4, byteorder=State.ENDIAN)[offset]

    def set_byte(self, byte, i):
        row, col, offset = State._linear_to_rco(i)
        lane = bytearray(self.planes[row][col].to_bytes(4, byteorder=State.ENDIAN))
        lane[offset] = byte
        self.planes[row][col] = int.from_bytes(lane, State.ENDIAN)

    def dump(self, msg, lvl):
        if lvl == VERBOSE_LEVEL:
            print(f'[PY] {msg:16.16}: {self}')

class LwcAead:
    def encrypt(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> bytes:
        ...

    def decrypt(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bool, bytes]:
        ...

class LwcHash:
    def hash(self, msg: bytes) -> bytes:
        ...

class XoodyakCref(LwcCffi, LwcAead, LwcHash):
    cand_name = 'xoodyakv1'
    root_cref_dir = Path('cref')

    def __init__(self, force_recompile=False) -> None:
        # TODO move dynamic (compile +) loading to LwcCffi
        try:
            if force_recompile:
                raise ModuleNotFoundError
            from _xoodyakv1_hash import ffi as hash_ffi, lib as hash_lib
            from _xoodyakv1_aead import ffi as aead_ffi, lib as aead_lib
        except ModuleNotFoundError as e:
            print('Need to build the library...')
            self.build_cffi(self.root_cref_dir, self.cand_name)
            from _xoodyakv1_hash import ffi as hash_ffi, lib as hash_lib
            from _xoodyakv1_aead import ffi as aead_ffi, lib as aead_lib

        self.aead_lib = aead_lib
        self.aead_ffi = aead_ffi
        self.hash_lib = hash_lib
        self.hash_ffi = hash_ffi

    def encrypt(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> bytes:
        assert len(key) == self.aead_lib.CRYPTO_KEYBYTES
        assert len(nonce) == self.aead_lib.CRYPTO_NPUBBYTES
        ct = bytes(len(pt) + self.aead_lib.CRYPTO_ABYTES)
        ct_len = self.aead_ffi.new('unsigned long long*')

        ret = self.aead_lib.crypto_aead_encrypt(ct, ct_len, pt, len(pt), ad, len(ad), self.aead_ffi.NULL, nonce, key)
        assert ret == 0
        assert ct_len[0] == len(ct)

        return ct

    def decrypt(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bool, bytes]:
        ct_len = len(ct)
        assert len(key) == self.aead_lib.CRYPTO_KEYBYTES
        assert len(nonce) == self.aead_lib.CRYPTO_NPUBBYTES
        assert ct_len >= TAGLEN, "ct should contain TAG"
        pt = bytes(ct_len - TAGLEN)
        pt_len = self.aead_ffi.new('unsigned long long*')

        ret = self.aead_lib.crypto_aead_decrypt(pt, pt_len, self.aead_ffi.NULL, ct, ct_len, ad, len(ad), nonce, key)
        assert (ret != 0 and pt_len[0] == 0) or pt_len[0] == ct_len - TAGLEN

        return ret == 0, pt

    def hash(self, msg: bytes) -> bytes:
        out = bytes(self.hash_lib.CRYPTO_BYTES)
        ret = self.hash_lib.crypto_hash(out, msg, len(msg))
        assert ret == 0
        return out


class Xoodoo:    
    def __init__(self):
        self.state = State()
        rc_s = []
        rc_p = []
        s = 1
        for _ in range(6):
            rc_s.append(s)
            s = (s * 5) % 7
        p = 1
        for _ in range(7):
            rc_p.append(p)
            p = p ^ (p << 2)
            if (p & 0b10000) != 0:
                p ^= 0b10110
            if (p & 0b01000) != 0:
                p ^= 0b01011
        self.rcs = [(rc_p[-j % 7] ^ 0b1000) << rc_s[-j % 6] for j in range(-11, 1)]

    def initialize(self):
        self.state.set_zero()

    def permute(self, r=12):
        for i in range(0, r):
            self.round(i)

    def round(self, i):
        # reference to state
        A = self.state

        # θ
        P = A[0] ^ A[1] ^ A[2]
        E = P.cyclic_shift(1, 5) ^ P.cyclic_shift(1, 14)
        for y in range(3):
            A[y] ^= E

        # ρ_west
        A[1] = A[1].cyclic_shift(1, 0)
        A[2] = A[2].cyclic_shift(0, 11)

        # ι
        # rc = (self.rc_p[-i % 7] ^ 0b1000) << self.rc_s[-i % 6]
        # print(rc, end=', ')
        A[0][0] ^= self.rcs[i]

        # χ
        for y in range(3):
            A[y] ^= (~A[(y+1) % 3] & A[(y + 2) % 3])

        # ρ_east
        A[1] = A[1].cyclic_shift(0, 1)
        A[2] = A[2].cyclic_shift(2, 8)

    def __getitem__(self, i):
        return self.state.get_byte(i)

    def __setitem__(self, i, v):
        self.state.set_byte(v, i)

    def add_byte(self, byte, offset: int):
        row, col, byte_offset = State._linear_to_rco(offset)
        self.state.planes[row][col] ^= (byte << (byte_offset * 8))
        # self.state.set_byte(byte ^ self.state.get_byte(offset), offset)

    def add_last_byte(self, byte):
        self.state.planes[-1][-1] ^= (byte << 24)

    def add_bytes(self, data: bytes, offset: int = 0):
        data_offset = 0
        # never
        while offset % LANE_BYTES != 0:
            self.add_byte(data[data_offset], offset)
            data_offset += 1
            offset += 1

        for i in range(data_offset, len(data), LANE_BYTES):
            row, col = State._row_cols(i)
            self.state[row][col] ^= int.from_bytes(data[i:i+LANE_BYTES], State.ENDIAN)
            data_offset += LANE_BYTES

        for i, d in enumerate(data[data_offset:]):
            self.add_byte(d, i + offset)

        # unoptimized:
        # for i, d in enumerate(data):
        #     self.add_byte(d, i + offset)

    def extract_and_addbytes(self, input: bytes, offset: int = 0) -> bytes:
        ilen = len(input)
        assert offset < STATE_BYTES
        assert offset + ilen < STATE_BYTES
        return bytes(self[offset + i] ^ input[i] for i in range(ilen))

    def extract_bytes(self, offset: int, length: int) -> bytes:
        assert offset < STATE_BYTES
        assert offset + length < STATE_BYTES
        return bytes(self.state.get_byte(i + offset) for i in range(length))


class Cyclist:
    class Phase(Enum):
        Up = auto()
        Down = auto()

    class Mode(Enum):
        Hash = auto()
        Keyed = auto()

    def __init__(self) -> None:
        self.xoodoo = Xoodoo()
        self.initialize()

    def initialize(self, key=None) -> None:
        self.xoodoo.initialize()
        self.r_absorb = Xoodyak_Rhash
        self.r_squeeze = Xoodyak_Rhash
        self.phase = Cyclist.Phase.Up
        self.mode = Cyclist.Mode.Hash
        if key:
            assert len(key) == CRYPTO_KEYBYTES
            self._absorb_key(key)

    def dump_state(self, msg, lvl):
        self.xoodoo.state.dump(msg, lvl)

    def up(self, out_len: int, cu: int) -> Optional[bytes]:
        if self.mode != Cyclist.Mode.Hash:
            self.xoodoo.add_byte(cu, Xoodyak_f_bPrime - 1)
        self.xoodoo.permute()
        self.phase = Cyclist.Phase.Up
        if out_len != 0:
            return None
        return self.xoodoo.extract_bytes(0, out_len)

    def down(self, x: bytes = b'', cd: int = 0) -> None:
        self.xoodoo.add_bytes(x + b'\x01')
        if self.mode == Cyclist.Mode.Hash:
            cd &= 0x01
        self.xoodoo.add_byte(cd, Xoodyak_f_bPrime - 1)
        self.phase = Cyclist.Phase.Down

    def crypt(self, input: bytes, decrypt: bool) -> bytes:
        assert self.mode == Cyclist.Mode.Keyed
        cu = 0x80
        io_len = len(input)
        out = bytearray(io_len)
        io_offset = 0

        while True:
            split_len = min(io_len, Xoodyak_Rkout)
            p = input[io_offset: io_offset + split_len]
            self.up(0, cu)
            out[io_offset: io_offset + split_len] = self.xoodoo.extract_and_addbytes(p)
            if decrypt:
                p = out[io_offset: io_offset + split_len]
            self.down(p, 0)
            cu = 0
            io_offset += split_len
            io_len -= split_len
            if io_len == 0:
                break
        return bytes(out)

    def _absorb_any(self, x: bytes, cd: int, r: int = None) -> None:
        if r is None:
            r = self.r_absorb
        xlen = len(x)
        xoff = 0
        while True:
            if self.phase != Cyclist.Phase.Up:
                self.up(0, 0)
            split_len = min(xlen, r)
            self.down(x[xoff:xoff+split_len], cd)
            cd = 0
            xoff += split_len
            xlen -= split_len
            if xlen == 0:
                break

    def absorb(self, x: bytes) -> None:
        self._absorb_any(x, 0x03)

    def _absorb_key(self, key: bytes, id: bytes = b'', counter: bytes = None) -> None:
        assert self.mode == Cyclist.Mode.Hash
        self.mode = Cyclist.Mode.Keyed
        self.r_absorb = Xoodyak_Rkin
        self.r_squeeze = Xoodyak_Rkout
        self._absorb_any(key + id + bytes([len(id)]), 0x02)
        if counter:
            self._absorb_any(counter, 0x00, r=1)

    def _squeeze_any(self, olen: int, cu: int) -> bytes:
        out = bytearray(olen)
        out_offset = 0
        while olen != 0:
            if out_offset > 0:
                self.down()
            seg_len = min(olen, self.r_squeeze)
            out[out_offset:out_offset + seg_len] = self.up(seg_len, cu)
            cu = 0
            out_offset += seg_len
            olen -= seg_len
        return bytes(out)

    def squeeze(self, olen: int) -> bytes:
        return self._squeeze_any(olen, 0x40)


class Xoodyak(LwcAead, LwcHash):
    """Xoodyak interface for AEAD and Hash"""
    def __init__(self) -> None:
        self.cyclist = Cyclist()

    def encrypt_orig(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> bytes:
        self.cyclist.initialize(key)
        self.cyclist.dump_state(f'Aft. absorb key', 1)
        self.cyclist.absorb(nonce)
        self.cyclist.dump_state(f'Aft. absorb nonce', 1)
        self.cyclist.absorb(ad)
        self.cyclist.dump_state(f'Aft. absorb ad', 1)
        ct = self.cyclist.crypt(pt, decrypt=False)
        self.cyclist.dump_state(f'Aft. crypt ad', 1)
        tag = self.cyclist.squeeze(TAGLEN)
        return ct + tag

    def decrypt_orig(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bool,Optional[bytes]]:
        if len(ct) < TAGLEN:
            return False, None
        self.cyclist.initialize(key)
        self.cyclist.absorb(nonce)
        self.cyclist.absorb(ad)
        pt = self.cyclist.crypt(ct[:-TAGLEN], decrypt=True)
        tag = self.cyclist.squeeze(TAGLEN)
        if ct[-TAGLEN:] != tag:
            return False, bytes(len(ct) - TAGLEN)
        return True, pt

    def hash_orig(self, msg: bytes) -> bytes:
        self.cyclist.initialize()
        self.cyclist.absorb(msg)
        return self.cyclist.squeeze(CRYPTO_HASH_BYTES)

    def encrypt(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> bytes:
        return self.crypt(pt, ad, nonce, key, decrypt=False)

    def crypt(self, in_bytes: bytes, ad: bytes, nonce: bytes, key: bytes, decrypt=False) -> Union[bytes, Tuple[bool, Optional[bytes]]]:
        if decrypt and len(in_bytes) < TAGLEN:
            return False, None
        self.cyclist.xoodoo.initialize()

        self.cyclist.xoodoo.add_bytes(key + bytes([0]) + b'\x01')
        self.cyclist.xoodoo.add_last_byte(0x02)
        self.cyclist.dump_state('before key perm', 1)
        self.cyclist.xoodoo.permute()
        self.cyclist.dump_state('after key perm', 1)
        
        self.cyclist.xoodoo.add_bytes(nonce + b'\x01')
        self.cyclist.xoodoo.add_last_byte(0x03)
        self.cyclist.dump_state('before nonce perm', 1)
        self.cyclist.xoodoo.permute()
        self.cyclist.dump_state('after nonce perm', 1)

        #self.cyclist.absorb(ad)
        xlen = len(ad)
        xoff = 0
        first = True
        while True:
            split_len = min(xlen, Xoodyak_Rkin)
            self.cyclist.xoodoo.add_bytes(ad[xoff:xoff+split_len] + b'\x01')
            xoff += split_len
            xlen -= split_len
            if xlen == 0:
                self.cyclist.xoodoo.add_last_byte(0x83 if first else 0x80)
                self.cyclist.dump_state('before ad perm (last)', 1)
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('after ad perm (last)', 1)
                break
            else:
                self.cyclist.xoodoo.add_last_byte(0x03 if first else 0)
                self.cyclist.dump_state('before ad perm', 1)
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('after ad perm', 1)
                first = False

        io_len = len(in_bytes)
        if decrypt:
            io_len -= TAGLEN

        out_bytes = bytearray(io_len)
        io_offset = 0
        while True:
            split_len = min(io_len, Xoodyak_Rkout)
            out_bytes[io_offset: io_offset + split_len] = bytes(self.cyclist.xoodoo[i] ^ in_bytes[io_offset + i] for i in range(split_len))
            print(f'out_bytes={out_bytes.hex()}')
            x = out_bytes[io_offset: io_offset + split_len] if decrypt else in_bytes[io_offset: io_offset + split_len]
            self.cyclist.xoodoo.add_bytes(x + b'\x01')
            io_offset += split_len
            io_len -= split_len
            if io_len == 0:
                self.cyclist.xoodoo.add_last_byte(0x40)
                self.cyclist.dump_state('b4 PT Perm.last', 1)
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('af PT Perm.last', 1)
                break
            else:
                self.cyclist.dump_state('b4 PT perm', 1)
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('af PT perm', 1)

        tag = bytes(self.cyclist.xoodoo[i] for i in range(TAGLEN))

        if decrypt:
            if in_bytes[-TAGLEN:] != tag:
                return False, bytes(len(in_bytes) - TAGLEN)
            return True, out_bytes

        print(f'output: {(out_bytes + tag).hex()}')
        return out_bytes + tag

    def decrypt(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bool, Optional[bytes]]:
        return self.crypt(ct, ad, nonce, key, decrypt=True)

    def hash(self, msg: bytes) -> bytes:
        self.cyclist.xoodoo.initialize()
        # absorb msg
        xlen = len(msg)
        xoff = 0
        first = True
        while True:
            split_len = min(xlen, Xoodyak_Rhash)
            self.cyclist.xoodoo.add_bytes(msg[xoff:xoff+split_len] + b'\x01')
            self.cyclist.xoodoo.add_last_byte(0x01 if first else 0)
            first = False
            self.cyclist.xoodoo.permute()
            xoff += split_len
            xlen -= split_len
            if xlen == 0:
                break
        # squeeze hash
        h0 = bytes(self.cyclist.xoodoo.state.get_byte(i) for i in range(Xoodyak_Rhash))
        self.cyclist.xoodoo.add_byte(0x01, 0)
        self.cyclist.xoodoo.permute()
        h1 = bytes(self.cyclist.xoodoo.state.get_byte(i) for i in range(Xoodyak_Rhash))

        return h0 + h1


## Testing (compatible with pytest and pytest-xdist)
# run with pytest-xdist:
# pytest -n 8 xoodyak.py

def rand_bytes(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))


def test_decrypt():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for pt_len in range(100, 120):
        # print(f'[D] ct_len={pt_len}')
        for ad_len in range(0, 100):
            pt = rand_bytes(pt_len)
            ad = rand_bytes(ad_len)
            nonce = rand_bytes(CRYPTO_NPUBBYTES)
            key = rand_bytes(CRYPTO_KEYBYTES)
            ct = cref.encrypt(pt, ad, nonce, key)
            ct2 = pyref.encrypt(pt, ad, nonce, key)
            # print(ct.hex().upper())
            assert ct2 == ct
            decrypt_success, pt2 = pyref.decrypt(ct, ad, nonce, key)
            assert decrypt_success and pt2 and pt2 == pt
            # print(ct.hex().upper())


def test_hash():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for msg_len in range(0, 1000):
        # print(f'[H] msg_len={msg_len}')
        msg = rand_bytes(msg_len)
        py_hash = pyref.hash(msg)
        c_hash = cref.hash(msg)
        # print(f'{py_hash.hex()}')
        assert py_hash == c_hash


def test_encrypt_small():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for pt_len in range(0, 100):
        # print(f'pt_len={pt_len}')
        for ad_len in range(0, 100):
            pt = rand_bytes(pt_len)
            ad = rand_bytes(ad_len)
            nonce = rand_bytes(CRYPTO_NPUBBYTES)
            key = rand_bytes(CRYPTO_KEYBYTES)
            ct = cref.encrypt(pt, ad, nonce, key)
            ct2 = pyref.encrypt(pt, ad, nonce, key)
            assert ct2 == ct
            success, pt2 = cref.decrypt(ct, ad, nonce, key)
            assert success
            # print(ct.hex().upper())
            assert pt2 == pt, f'pt2:{pt2} != pt:{pt}'


def test_decrypt_fail():
    cref = XoodyakCref()
    pyref = Xoodyak()
    for ct_len in range(TAGLEN, TAGLEN + 100):
        for ad_len in range(0, 10):
            ct = rand_bytes(ct_len)
            ad = rand_bytes(ad_len)
            nonce = rand_bytes(CRYPTO_NPUBBYTES)
            key = rand_bytes(CRYPTO_KEYBYTES)
            success1, pt1 = cref.decrypt(ct, ad, nonce, key)
            success2, pt2 = pyref.decrypt(ct, ad, nonce, key)
            assert success1 == success2
            assert pt1 == pt2, f'pt1:{pt1} != pt2:{pt2}'
            assert not success1


if __name__ == "__main__":
    test_encrypt_small()
    test_decrypt_fail()
    test_decrypt()
    test_hash()
