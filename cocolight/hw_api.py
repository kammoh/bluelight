from enum import IntEnum
from typing import List

from .utils import bytes_to_words

API_BYTEORDER = 'big'  # HW API is big-endian


class SegmentType(IntEnum):
    @staticmethod
    def from_byte(b):
        return SegmentType(b)

    AD = 0b0001
    PT = 0b0100
    CT = 0b0101
    TAG = 0b1000
    KEY = 0b1100
    NPUB = 0b1101
    HM = 0b0111
    DIGEST = 0b1001
    LENGTH = 0b1010


class SegmentHeader():
    def __init__(self, segment_type: SegmentType, len: int, last, eot, eoi, partial=0) -> None:
        self.type: SegmentType = segment_type
        self.len: int = len
        self.partial = partial
        self.eoi = eoi
        self.eot = eot
        self.last = last

    def __str__(self):
        s = f'{self.type.name} {self.len} Bytes'
        if self.eoi:
            s += ' EOI'
        if self.eot:
            s += ' EOT'
        if self.last:
            s += ' Last'
        if self.partial:
            s += ' Partial'
        return s

    @classmethod
    def from_word32(cls, w: int) -> 'SegmentHeader':
        sn = (w >> 24) & 0xf
        return SegmentHeader(SegmentType.from_byte((w >> 28) & 0xf), len=(w >> 16) & 0xffff, last=sn & 1, eot=(sn >> 1) & 1, eoi=(sn >> 2) & 1, partial=(sn >> 3) & 1)

    # FIXME IO_WIDTH != 32
    # ...  def from_words to_words

    # FIXME IO_WIDTH != 32
    def __int__(self):
        return self.to_word32()

    def to_word32(self) -> int:
        assert self.last is not None
        assert self.eoi is not None
        assert self.eot is not None
        return (int(self.type) << 28) | (self.partial << 27) | (
            self.eoi << 26) | (self.eot << 25) | (self.last << 24) | (self.len & 0xffff)

    def to_words(self, width):
        # FIXME IO_WIDTH != 32
        return [self.to_word32()]


class Segment:
    def __init__(self, segment_type: SegmentType, data: bytes, last=None, eot=None, eoi=None, partial=0) -> None:
        assert isinstance(data, bytearray) or isinstance(
            data, bytes), f"data must be bytearray/bytes but was {type(data)}"
        self.header = SegmentHeader(segment_type,
                                    len(data), last=last, eot=eot, eoi=eoi, partial=partial)
        self.data = data

    @staticmethod
    def segmentize(segment_type: SegmentType, data: bytes, last=None, eot=None, eoi=None, partial=0, max_bytes=2**15) -> List['Segment']:
        if len(data) == 0:
            return [Segment(segment_type, data, last=last, eot=eot, eoi=eoi, partial=partial)]
        return [Segment(segment_type, data[i:i + max_bytes], last=last, eot=eot, eoi=eoi, partial=partial) for i in range(0, len(data), max_bytes)]

    @property
    def type(self):
        return self.header.type

    @property
    def len(self):
        return self.header.len

    def to_words(self, width):
        return self.header.to_words(width) + bytes_to_words(self.data, width, API_BYTEORDER)


class OpCode(IntEnum):
    HASH = 0b1000
    ENC = 0b0010
    DEC = 0b0011
    LDKEY = 0b0100
    ACTKEY = 0b0111


class Instruction:
    def __init__(self, op_code: OpCode) -> None:
        self.op: OpCode = op_code

    @classmethod
    def from_word(cls, w):
        return Instruction(op_code=OpCode((w >> 12) & 0xf))

    def to_word32(self, width):
        return int(self.op) << (width - 4)

    def to_words(self, width):
        return [self.to_word32(width)]  # FIXME io_width

    def __str__(self):
        return f'{self.op.name}'


class Status(IntEnum):
    Success = 0xe
    Failure = 0xf

    def to_words(self, width) -> int:
        return [int(self) << (width - 4)]
