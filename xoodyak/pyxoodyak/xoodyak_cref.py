
import sys
import random
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional, Tuple, Union
import os
import inspect

SCRIPT_DIR = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))


DEBUG_LEVEL = 0
from .lwc_api import LwcAead, LwcHash, LwcCffi


class XoodyakCref(LwcCffi, LwcAead, LwcHash):
    aead_algorithm = 'xoodyakv1'
    hash_algorithm = 'xoodyakv1'
    root_cref_dir = Path(SCRIPT_DIR).parent / 'cref'

    def encrypt(self, pt: bytes, ad: bytes, nonce: bytes, key: bytes) -> Tuple[bytes, bytes]:
        assert len(key) == self.aead_lib.CRYPTO_KEYBYTES
        assert len(nonce) == self.aead_lib.CRYPTO_NPUBBYTES
        ct = bytes(len(pt) + self.aead_lib.CRYPTO_ABYTES)
        ct_len = self.aead_ffi.new('unsigned long long*')

        ret = self.aead_lib.crypto_aead_encrypt(ct, ct_len, pt, len(
            pt), ad, len(ad), self.aead_ffi.NULL, nonce, key)
        assert ret == 0
        assert ct_len[0] == len(ct)
        tag = ct[-self.CRYPTO_ABYTES:]
        ct = ct[:-self.CRYPTO_ABYTES]
        return tag, ct

    def decrypt(self, ct: bytes, ad: bytes, nonce: bytes, key: bytes, tag: bytes) -> Tuple[bool, bytes]:
        ct_len = len(ct)
        assert len(key) == self.aead_lib.CRYPTO_KEYBYTES
        assert len(nonce) == self.aead_lib.CRYPTO_NPUBBYTES
        pt = bytes(ct_len)
        assert len(tag) == self.CRYPTO_ABYTES, f"Tag should be {self.CRYPTO_ABYTES} bytes"
        pt_len = self.aead_ffi.new('unsigned long long*')
        ct_tag = self.aead_ffi.from_buffer(ct + tag)
        ret = self.aead_lib.crypto_aead_decrypt(
            pt, pt_len, self.aead_ffi.NULL, ct_tag, ct_len + self.CRYPTO_ABYTES, ad, len(ad), nonce, key)
        assert (ret != 0 and pt_len[0] == 0) or pt_len[0] == ct_len

        return ret == 0, pt

    def hash(self, msg: bytes) -> bytes:
        out = bytes(self.hash_lib.CRYPTO_BYTES)
        ret = self.hash_lib.crypto_hash(out, msg, len(msg))
        assert ret == 0
        return out
