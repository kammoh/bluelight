from typing import Tuple
from typeguard import typechecked
import inspect
import sys
import os
from hacspec import speclib


SCRIPT_DIR = os.path.realpath(os.path.dirname(
    inspect.getfile(inspect.currentframe())))

COCOLIGHT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.append(COCOLIGHT_DIR)
sys.path.append(SCRIPT_DIR)

try:
    from gimli_cipher import gimli_aead_encrypt, gimli_aead_decrypt
    from gimli_hash import gimli_hash
except:
    from .gimli_cipher import gimli_aead_encrypt, gimli_aead_decrypt
    from .gimli_hash import gimli_hash

from cocolight.lwc_api import LwcAead, LwcHash, tag_type
from cocolight.bluespec_interface import *
from cocolight.lwc_api import LwcAead, LwcHash, LwcCffi, tag_type
from cocolight.utils import rand_bytes



class GimliPyRef(LwcAead, LwcHash):
    CRYPTO_KEYBYTES = 32
    CRYPTO_NPUBBYTES = 16
    CRYPTO_ABYTES = 16

    CRYPTO_HASH_BYTES = 32

    @staticmethod
    def to_array(b: bytes) -> speclib.array:
        return speclib.array([speclib.uint8(x) for x in b])

    def to_bytes(a: speclib.array) -> bytes:
        return bytes([int(x) for x in a])

    @typechecked
    def encrypt(self, pt: bytes, ad: bytes, npub: bytes, key: bytes) -> Tuple[bytes, tag_type]:
        pt = GimliPyRef.to_array(pt)
        ad = GimliPyRef.to_array(ad)
        npub = GimliPyRef.to_array(npub)
        key = GimliPyRef.to_array(key)
        ct, tag = gimli_aead_encrypt(pt, ad, npub, key)
        return GimliPyRef.to_bytes(ct), GimliPyRef.to_bytes(tag)

    def decrypt(self, ct: bytes, ad: bytes, npub: bytes, key: bytes, tag: tag_type) -> bytes:
        """ returns pt if tag matches o/w None """
        ct = GimliPyRef.to_array(ct)
        ad = GimliPyRef.to_array(ad)
        npub = GimliPyRef.to_array(npub)
        key = GimliPyRef.to_array(key)
        ct = gimli_aead_decrypt(ct, ad, tag, npub, key)
        return GimliPyRef.to_bytes(ct)

    @typechecked
    def hash(self, msg: bytes) -> bytes:
        msg = GimliPyRef.to_array(msg)
        return GimliPyRef.to_bytes(gimli_hash(msg, len(msg)))