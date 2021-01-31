#!/usr/bin/python3

from hacspec.speclib import *

from gimli import gimli

state_t = array_t(uint32_t, 12)
rate : nat_t = 16

@typechecked
def absorb_block(input_block: vlbytes_t, s: state_t) -> state_t:
    s[0] ^= bytes.to_uint32_le(input_block[0:4])
    s[1] ^= bytes.to_uint32_le(input_block[4:8])
    s[2] ^= bytes.to_uint32_le(input_block[8:12])
    s[3] ^= bytes.to_uint32_le(input_block[12:16])
    s = gimli(s)
    return s

@typechecked
def squeeze_block(s: state_t) -> bytes_t:
    block : bytes_t = array.create(rate, uint8(0))
    for i in range(4):
        block[4*i:4*(i + 1)] = bytes.from_uint32_le(s[i])
    return block

@typechecked
def gimli_hash(input_bytes: vlbytes_t, input_length: int) -> bytes_t:
    s : state_t = array.create(12, uint32(0))
    # Absorb full blocks
    num_full_blocks: int = input_length // rate
    for i in range(num_full_blocks):
        message_block : bytes_t = input_bytes[rate*i : rate* (i + 1)]
        s = absorb_block(message_block, s)

    # Absorb last incomplete block
    bytes_left: int = input_length % rate
    last_block: bytes_t = array.create(rate, uint8(0))
    last_block[0:bytes_left] = input_bytes[(input_length - bytes_left):input_length]
    last_block[bytes_left] = uint8(1)

    # XOR in capacity part
    s[11] ^= uint32(0x01000000)
    s = absorb_block(last_block, s)

    output: bytes_t = array.create(32, uint8(0))
    output[0:rate] = squeeze_block(s)
    s = gimli(s)
    output[rate:2*rate] = squeeze_block(s)
    return output
