# Xoodyak Lightweight AEAD and Hash and verification against reference C code
# Xoodyak, Cyclist, and XoodyakCref implementation by Kamyar Mohajerani <kamyar@ieee.org>
#
# "Xoodoo" class is mostly based on Python code by Seth Hoffert,
#  available from https://github.com/KeccakTeam/Xoodoo/blob/master/Reference/Python/Xoodoo.py
# and the reference C implementation.

import sys
from enum import Enum, auto
from typing import Any, Optional, Tuple
import os
import inspect

SCRIPT_DIR = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

DEBUG_LEVEL = 1

from .lwc_api import LwcAead, LwcHash



Xoodyak_f_bPrime = 48
Xoodyak_Rhash = 16
Xoodyak_Rkin = 44
Xoodyak_Rkout = 24



class Plane:
    NCOLUMNS = 4

    def __init__(self, lanes=None):
        if lanes is None:
            lanes = [0] * self.NCOLUMNS
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
        return Plane([~self.lanes[x] for x in range(self.NCOLUMNS)])

    def cyclic_shift(self, dx, dz) -> 'Plane':
        def cyclic_shift_lane(lane, dz):
            if dz == 0:
                return lane
            return ((lane >> (32 - dz)) | (lane << dz)) % (1 << 32)
        return Plane([cyclic_shift_lane(self.lanes[(i - dx) % self.NCOLUMNS], dz) for i in range(self.NCOLUMNS)])


class State:
    ENDIAN = sys.byteorder
    NROWS = 3
    LANE_BYTES = 4
    
    @staticmethod
    @property
    def NLANES():
        return State.NROWS * Plane.NCOLUMNS

    @staticmethod
    @property
    def STATE_BYTES(self):
        return State.LANE_BYTES * State.NLANES

    def __init__(self):
        self.planes = [Plane() for _ in range(State.NROWS)]

    def __getitem__(self, i):
        return self.planes[i]

    def __setitem__(self, i, v):
        self.planes[i] = v

    def __str__(self):
        return ' - '.join(str(x) for x in self.planes)

    def set_zero(self):
        for i in range(self.NROWS):
            for j in range(Plane.NCOLUMNS):
                self.planes[i][j] = 0

    @staticmethod
    def _row_cols(i):
        plane_bytes = State.LANE_BYTES * Plane.NCOLUMNS
        assert i < plane_bytes * State.NROWS
        row = i // plane_bytes
        col = (i % plane_bytes) // State.LANE_BYTES
        return row, col

    @staticmethod
    def _linear_to_rco(i):
        """convert linear byte address to (row, column, offset)"""
        row, col = State._row_cols(i)
        offset = i % State.LANE_BYTES
        assert row < State.NROWS and col < Plane.NCOLUMNS
        return row, col, offset

    def get_byte(self, i):
        row, col, offset = State._linear_to_rco(i)
        lane = self.planes[row][col]
        return lane.to_bytes(4, byteorder=State.ENDIAN)[offset]

    def set_byte(self, byte, i):
        row, col, offset = State._linear_to_rco(i)
        lane = bytearray(self.planes[row][col].to_bytes(
            4, byteorder=State.ENDIAN))
        lane[offset] = byte
        self.planes[row][col] = int.from_bytes(lane, State.ENDIAN)



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
        self.rcs = [(rc_p[-j % 7] ^ 0b1000) << rc_s[-j % 6]
                    for j in range(-11, 1)]

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
        while offset % State.LANE_BYTES != 0:
            self.add_byte(data[data_offset], offset)
            data_offset += 1
            offset += 1

        for i in range(data_offset, len(data), State.LANE_BYTES):
            row, col = State._row_cols(i)
            self.state[row][col] ^= int.from_bytes(
                data[i:i+State.LANE_BYTES], State.ENDIAN)
            data_offset += State.LANE_BYTES

        for i, d in enumerate(data[data_offset:]):
            self.add_byte(d, i + offset)

        # unoptimized:
        # for i, d in enumerate(data):
        #     self.add_byte(d, i + offset)

    def extract_and_addbytes(self, input: bytes, offset: int = 0) -> bytes:
        ilen = len(input)
        assert offset < State.STATE_BYTES
        assert offset + ilen < State.STATE_BYTES
        return bytes(self[offset + i] ^ input[i] for i in range(ilen))

    def extract_bytes(self, offset: int, length: int) -> bytes:
        assert offset < State.STATE_BYTES
        assert offset + length < State.STATE_BYTES
        return bytes(self.state.get_byte(i + offset) for i in range(length))


class Cyclist:
    CRYPTO_KEYBYTES = 16

    class Phase(Enum):
        Up = auto()
        Down = auto()

    class Mode(Enum):
        Hash = auto()
        Keyed = auto()

    def __init__(self, debug=False) -> None:
        self.xoodoo = Xoodoo()
        self.initialize()
        self.debug=debug
        if self.debug:
            print("Cyclist is in Debug mode!")

    def log(self, *args, **kwargs):
        if self.debug:
            print(*args, **kwargs)

    def initialize(self, key=None) -> None:
        self.xoodoo.initialize()
        self.r_absorb = Xoodyak_Rhash
        self.r_squeeze = Xoodyak_Rhash
        self.phase = Cyclist.Phase.Up
        self.mode = Cyclist.Mode.Hash
        if key:
            assert len(key) == self.CRYPTO_KEYBYTES
            self._absorb_key(key)

    def dump_state(self, msg):
        self.log(f'{msg:16.16} {self.xoodoo.state}')

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
            out[io_offset: io_offset +
                split_len] = self.xoodoo.extract_and_addbytes(p)
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
    aead_algorithm = 'xoodyakv1'
    hash_algorithm = 'xoodyakv1'

    CRYPTO_KEYBYTES = Cyclist.CRYPTO_KEYBYTES
    CRYPTO_NPUBBYTES = 16
    CRYPTO_HASH_BYTES = 32
    CRYPTO_ABYTES = 16


    def __init__(self, debug=False) -> None:
        print(f"PyXoodyak: debug={debug}")
        self.cyclist = Cyclist(debug=debug)
        self.debug = debug
        if self.debug:
            print(f'Xoodyak is in Debug ({self.debug}) mode!')

    def log(self, *args, **kwargs):
        if self.debug:
            print(*args, **kwargs)

    def encrypt_orig(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> bytes:
        self.cyclist.initialize(key)
        self.cyclist.dump_state(f'Aft. absorb key')
        self.cyclist.absorb(nonce)
        self.cyclist.dump_state(f'Aft. absorb nonce')
        self.cyclist.absorb(ad)
        self.cyclist.dump_state(f'Aft. absorb ad')
        ct = self.cyclist.crypt(pt, decrypt=False)
        self.cyclist.dump_state(f'Aft. crypt ad')
        tag = self.cyclist.squeeze(self.CRYPTO_ABYTES)
        return tag, ct

    def decrypt_orig(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bool, Optional[bytes]]:
        if len(ct) < self.CRYPTO_ABYTES:
            return False, None
        self.cyclist.initialize(key)
        self.cyclist.absorb(nonce)
        self.cyclist.absorb(ad)
        pt = self.cyclist.crypt(ct[:-self.CRYPTO_ABYTES], decrypt=True)
        tag = self.cyclist.squeeze(self.CRYPTO_ABYTES)
        if ct[-self.CRYPTO_ABYTES:] != tag:
            return False, bytes(len(ct) - self.CRYPTO_ABYTES)
        return True, pt

    def hash_orig(self, msg: bytes) -> bytes:
        self.cyclist.initialize()
        self.cyclist.absorb(msg)
        return self.cyclist.squeeze(self.CRYPTO_HASH_BYTES)

    def encrypt(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bytes, bytes]:
        return self.crypt(pt, ad, nonce, key)

    def crypt(self, in_bytes: bytes, ad: bytes, nonce: bytes, key: bytes, tag=None) -> Tuple[Any, bytes]:
        decrypt = tag is not None

        self.cyclist.xoodoo.initialize()

        self.cyclist.xoodoo.add_bytes(key + bytes([0]) + b'\x01')
        self.cyclist.xoodoo.add_last_byte(0x02)
        # self.cyclist.dump_state('before key perm')
        self.cyclist.xoodoo.permute()
        # self.cyclist.dump_state('after key perm')

        self.cyclist.xoodoo.add_bytes(nonce + b'\x01')
        self.cyclist.xoodoo.add_last_byte(0x03)
        # self.cyclist.dump_state('before nonce perm')
        self.cyclist.xoodoo.permute()
        self.cyclist.dump_state('after nonce perm')

        # self.cyclist.absorb(ad)
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
                self.cyclist.dump_state('before ad perm (last)')
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('after ad perm (last)')
                break
            else:
                self.cyclist.xoodoo.add_last_byte(0x03 if first else 0)
                self.cyclist.dump_state('before ad perm')
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('after ad perm')
                first = False

        io_len = len(in_bytes)

        out_bytes = bytearray(io_len) # mutable version of bytes
        io_offset = 0
        while True:
            self.cyclist.dump_state('b4 add PT')
            split_len = min(io_len, Xoodyak_Rkout)
            self.log(f'adding: {(in_bytes[io_offset:io_offset+split_len]).hex()}')
            out_bytes[io_offset: io_offset + split_len] = bytes(
                self.cyclist.xoodoo[i] ^ in_bytes[io_offset + i] for i in range(split_len))
            self.log(f'out_bytes={out_bytes.hex()}')
            x = out_bytes[io_offset: io_offset +
                          split_len] if decrypt else in_bytes[io_offset: io_offset + split_len]
            self.cyclist.xoodoo.add_bytes(x + b'\x01')
            io_offset += split_len
            io_len -= split_len
            if io_len == 0:
                self.cyclist.xoodoo.add_last_byte(0x40)
                self.cyclist.dump_state('b4 PT Perm.last')
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('af PT Perm.last')
                break
            else:
                self.cyclist.dump_state('b4 PT perm')
                self.cyclist.xoodoo.permute()
                self.cyclist.dump_state('af PT perm')

        computed_tag = bytes(self.cyclist.xoodoo[i] for i in range(self.CRYPTO_ABYTES))

        out_bytes = bytes(out_bytes) # to immutable bytes TODO better (and still safe) way?

        if decrypt:
            tag_verified = computed_tag == tag
            pt = out_bytes if tag_verified else bytes(len(in_bytes))
            self.log(f'[Py] Tag Matched:{tag_verified} Plaintext: {pt.hex()}')
            return tag_verified, pt

        self.log(f'[Py] Tag: {computed_tag.hex()}\n     CT: {out_bytes.hex()}')
        return computed_tag, out_bytes

    def decrypt(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes, tag: bytes) -> Tuple[bool, bytes]:
        return self.crypt(ct, ad, nonce, key, tag)

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
            self.cyclist.dump_state('-bP_x')
            self.cyclist.xoodoo.permute()
            self.cyclist.dump_state('+aP_x')
            xoff += split_len
            xlen -= split_len
            if xlen == 0:
                break
        # squeeze hash
        h0 = bytes(self.cyclist.xoodoo.state.get_byte(i)
                   for i in range(Xoodyak_Rhash))
        self.log(f'[Py] h0={h0.hex()}')
        self.cyclist.xoodoo.add_byte(0x01, 0)

        self.cyclist.dump_state('-bP_Last')
        self.cyclist.xoodoo.permute()
        self.cyclist.dump_state('+aP_Last')
        h1 = bytes(self.cyclist.xoodoo.state.get_byte(i)
                   for i in range(Xoodyak_Rhash))
        self.log(f'[Py] h1={h1.hex()}')

        return h0 + h1
