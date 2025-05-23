import importlib
import importlib.util
import re
from cffi import FFI
import inspect
import os
from typing import Dict, Tuple
import sys
from pathlib import Path
from typeguard import typechecked
# from typeguard.importhook import install_import_hook

# install_import_hook("lwc_api")


# Proposed Python LWC API
# inspired from https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/final-lwc-submission-requirements-august2018.pdf

tag_type = bytes


class LwcAead:
    CRYPTO_KEYBYTES = None
    CRYPTO_NSECBYTES = None
    CRYPTO_NPUBBYTES = None
    CRYPTO_ABYTES = None

    @typechecked
    def encrypt(self, pt: bytes, ad: bytes, npub: bytes, key: bytes) -> Tuple[bytes, tag_type]:
        """returns ct, tag"""
        ...

    @typechecked
    def decrypt(self, ct: bytes, ad: bytes, npub: bytes, key: bytes, tag: tag_type) -> bytes:
        """returns pt if tag matches o/w None"""
        ...


class LwcHash:
    CRYPTO_HASH_BYTES = None

    @typechecked
    def hash(self, msg: bytes) -> bytes:
        ...


SCRIPT_DIR = os.path.realpath(os.path.dirname(inspect.getfile(inspect.currentframe())))


DEBUG_LEVEL = 0


def mylog(*args, **kwargs):
    if DEBUG_LEVEL > 0:
        print(*args, **kwargs)


class LwcCffi:
    """Python wrapper of C implementations, provides mechanism for building cpython native libs"""

    aead_algorithm = None
    hash_algorithm = None
    root_cref_dir = None

    CRYPTO_KEYBYTES = None
    CRYPTO_NSECBYTES = None
    CRYPTO_NPUBBYTES = None
    CRYPTO_ABYTES = None
    CRYPTO_HASH_BYTES = None

    def build_cffi(
        self,
        root_cref_dir: Path,
        algorithms: Dict[str, str],
        cffi_build_dir: str,
        DEBUG_LEVEL: int = 0,
    ):
        assert root_cref_dir
        headers = dict(
            aead="""
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
        );\n""",
            hash="int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long hlen);\n",
        )

        comments_pat = re.compile(r"(\/\*.*\*\/)*(\/\/.*)?")
        define_pat = re.compile(r"\#define\s+(\w+)\s+(\d+)")

        for op, algorithm in algorithms.items():
            if algorithm is None:
                continue
            header = headers[op]
            print(header)
            ffibuilder = FFI()
            cref_dir = root_cref_dir / f"crypto_{op}" / algorithm / "ref"
            hdr_file = cref_dir / f"crypto_{op}.h"
            if not hdr_file.exists():
                with open(hdr_file, "w") as f:
                    f.write(header)
            api_h = cref_dir / f"api.h"
            if api_h.exists():
                header += "\n"
                with open(api_h) as f:
                    for line in f.readlines():
                        line = re.sub(comments_pat, "", line)
                        line = line.strip()
                        m = define_pat.match(line)
                        if m:
                            header += line + "\n"

            ffibuilder.cdef(header)
            define_macros = []
            if DEBUG_LEVEL:
                define_macros.append(("DEBUG", DEBUG_LEVEL))
                define_macros.append(("ASCON_PRINT_STATE", 1))
                define_macros.append(("VERBOSE_LEVEL", DEBUG_LEVEL))
            ffibuilder.set_source(
                f"cffi_{algorithm}_{op}",
                header,
                libraries=[],
                sources=[str(s) for s in cref_dir.glob("*.c")],
                include_dirs=[cref_dir],
                define_macros=define_macros,
            )
            ffibuilder.compile(tmpdir=cffi_build_dir, verbose=1, target=None, debug=None)

    def __init__(
        self, cffi_build_dir="cffi_build", force_recompile=False, DEBUG_LEVEL=DEBUG_LEVEL
    ) -> None:
        assert self.aead_algorithm
        assert self.root_cref_dir

        self.cffi_build_dir = cffi_build_dir
        # sys.path.append(os.path.join(SCRIPT_DIR, cffi_build_dir))
        # print(f'adding {os.path.join(SCRIPT_DIR, cffi_build_dir)} to sys.path')
        sys.path.append(os.path.join(os.getcwd(), cffi_build_dir))
        print(f"adding {os.path.join(os.getcwd(), cffi_build_dir)} to sys.path")

        def try_imports():
            # from cffi_xoodyakv1_aead import ffi as aead_ffi, lib as aead_lib
            spec = importlib.util.find_spec(f"cffi_{self.aead_algorithm}_aead")
            if not spec:
                raise ModuleNotFoundError
            aead_module = spec.loader.load_module()
            self.aead_lib = aead_module.lib
            self.aead_ffi = aead_module.ffi
            # from cffi_xoodyakv1_hash import ffi as hash_ffi, lib as hash_lib

            assert self.aead_lib
            assert self.aead_ffi

            if self.hash_algorithm:
                spec = importlib.util.find_spec(f"cffi_{self.hash_algorithm}_hash")
                if not spec:
                    raise ModuleNotFoundError
                hash_module = spec.loader.load_module()
                self.hash_lib = hash_module.lib
                self.hash_ffi = hash_module.ffi
            else:
                self.hash_lib = None
                self.hash_ffi = None

        try:
            if force_recompile:
                raise ModuleNotFoundError
            try_imports()
        except ModuleNotFoundError as e:
            mylog("Need to build the library...")
            self.build_cffi(
                self.root_cref_dir,
                dict(aead=self.aead_algorithm, hash=self.hash_algorithm),
                self.cffi_build_dir,
                DEBUG_LEVEL=DEBUG_LEVEL,
            )
            importlib.invalidate_caches()
            sys.path.append(os.path.join(os.getcwd(), self.cffi_build_dir))
            print(f"adding {os.path.join(os.getcwd(), self.cffi_build_dir)} to sys.path")

            try:
                try_imports()
            except ModuleNotFoundError as e:
                print("You probably just need to run Python again. [Hopefully will be fixed soon] ")
                raise e

        self.CRYPTO_KEYBYTES = self.aead_lib.CRYPTO_KEYBYTES
        # self.CRYPTO_NSECBYTES = self.aead_lib.CRYPTO_NSECBYTES
        self.CRYPTO_NPUBBYTES = self.aead_lib.CRYPTO_NPUBBYTES
        self.CRYPTO_ABYTES = self.aead_lib.CRYPTO_ABYTES
        if self.hash_lib:
            self.CRYPTO_HASH_BYTES = self.hash_lib.CRYPTO_BYTES

    @typechecked
    def encrypt(self, pt: bytes, ad: bytes, npub: bytes, key: bytes) -> Tuple[bytes, tag_type]:
        """returns tag, ct"""
        assert len(key) == self.aead_lib.CRYPTO_KEYBYTES
        assert len(npub) == self.aead_lib.CRYPTO_NPUBBYTES
        ct = bytes(len(pt) + self.aead_lib.CRYPTO_ABYTES)
        ct_len = self.aead_ffi.new("unsigned long long*")

        ret = self.aead_lib.crypto_aead_encrypt(
            ct, ct_len, pt, len(pt), ad, len(ad), self.aead_ffi.NULL, npub, key
        )
        assert ret == 0
        assert ct_len[0] == len(ct)
        tag = ct[-self.CRYPTO_ABYTES :]
        ct = ct[: -self.CRYPTO_ABYTES]
        return ct, tag

    @typechecked
    def decrypt(self, ct: bytes, ad: bytes, npub: bytes, key: bytes, tag: bytes) -> bytes:
        ct_len = len(ct)
        assert len(key) == self.aead_lib.CRYPTO_KEYBYTES
        assert len(npub) == self.aead_lib.CRYPTO_NPUBBYTES
        pt = bytes(ct_len)
        assert len(tag) == self.CRYPTO_ABYTES, f"Tag should be {self.CRYPTO_ABYTES} bytes"
        pt_len = self.aead_ffi.new("unsigned long long*")
        ct_tag = self.aead_ffi.from_buffer(ct + tag)
        ret = self.aead_lib.crypto_aead_decrypt(
            pt,
            pt_len,
            self.aead_ffi.NULL,
            ct_tag,
            ct_len + self.CRYPTO_ABYTES,
            ad,
            len(ad),
            npub,
            key,
        )
        assert (ret != 0 and pt_len[0] == 0) or pt_len[0] == ct_len

        return pt if ret == 0 else None

    @typechecked
    def hash(self, msg: bytes) -> bytes:
        out = bytes(self.hash_lib.CRYPTO_BYTES)
        ret = self.hash_lib.crypto_hash(out, msg, len(msg))
        assert ret == 0
        return out
