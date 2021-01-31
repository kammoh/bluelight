#!/usr/bin/python3

from hacspec.speclib import *

from .gimli import gimli

rate: nat_t = 16
tlen: nat_t = 16

state_t = array_t(uint32_t, 12)
nonce_t = bytes_t(16)
key_t = bytes_t(32)
block_t = bytes_t(16)
tag_t = bytes_t(tlen)


@typechecked
def absorb_block(input_block: block_t, s: state_t) -> state_t:
    s[0] ^= bytes.to_uint32_le(input_block[0:4])
    s[1] ^= bytes.to_uint32_le(input_block[4:8])
    s[2] ^= bytes.to_uint32_le(input_block[8:12])
    s[3] ^= bytes.to_uint32_le(input_block[12:16])
    s = gimli(s)
    return s

@typechecked
def squeeze_block(s: state_t) -> bytes_t:
    block: bytes_t = array.create(rate, uint8(0))
    for i in range(4):
        block[4*i:4*(i + 1)] = bytes.from_uint32_le(s[i])
    return block

@typechecked
def process_ad(ad: vlbytes_t, adlen: int, s: state_t) -> state_t:
    # Complete blocks
    num_full_ad_blocks : int = adlen // rate
    for i in range(num_full_ad_blocks):
        ad_block: bytes_t = ad[rate*i : rate*(i + 1)]
        s = absorb_block(ad_block, s)

    # Last incomplete block
    bytes_left: int = adlen % rate
    last_block: bytes_t = array.create(rate, uint8(0))
    last_block[0:bytes_left] = ad[(adlen - bytes_left):]
    last_block[bytes_left] = uint8(1)
    s[11] ^= uint32(0x01000000)
    s = absorb_block(last_block, s)
    return s

@typechecked
def process_msg(message: vlbytes_t, mlen: int, s: state_t) -> Tuple[state_t, bytes_t]:
    ciphertext: bytes_t = array.create(mlen, uint8(0))

    num_full_msg_blocks: int = mlen // rate
    for i in range(num_full_msg_blocks):
        msg_block: bytes_t = message[rate*i : rate* (i + 1)]
        key_block: bytes_t = squeeze_block(s)
        for j in range(16):
            ciphertext[i*16 + j] = msg_block[j] ^ key_block[j]
        s = absorb_block(msg_block, s)

    bytes_left: int = mlen % rate
    key_block: bytes_t = squeeze_block(s)
    for i in range(bytes_left):
        ciphertext[mlen - bytes_left + i] = key_block[i] ^ message[mlen - bytes_left + i]

    last_block: bytes_t = array.create(rate, uint8(0))
    last_block[0:bytes_left] = message[(mlen - bytes_left):]
    last_block[bytes_left] = uint8(1)
    s[11] ^= uint32(0x01000000)
    s = absorb_block(last_block, s)

    return s, ciphertext

@typechecked
def process_ct(ciphertext: vlbytes_t, mlen: int, s: state_t) -> Tuple[state_t, bytes_t]:
    message: bytes_t = array.create(mlen, uint8(0))

    num_full_msg_blocks: int = mlen // rate
    for i in range(num_full_msg_blocks):
        ct_block: bytes_t = ciphertext[rate*i : rate* (i + 1)]
        key_block: bytes_t = squeeze_block(s)
        for j in range(16):
            ct_block[j] ^= key_block[j]
            message[i*16 + j] = ct_block[j]
        s = absorb_block(ct_block, s)

    bytes_left: int = mlen % rate
    key_block: bytes_t = squeeze_block(s)
    for i in range(bytes_left):
        message[mlen - bytes_left + i] = key_block[i] ^ ciphertext[mlen - bytes_left + i]

    last_block: bytes_t = array.create(rate, uint8(0))
    last_block[0:bytes_left] = message[(mlen - bytes_left):]
    last_block[bytes_left] = uint8(1)
    s[11] ^= uint32(0x01000000)
    s = absorb_block(last_block, s)

    return s, message

@typechecked
def gimli_aead_encrypt(message: vlbytes_t,
                       ad: vlbytes_t,
                       npub: nonce_t,
                       key: key_t) -> Tuple[vlbytes_t, tag_t]:
    s: state_t = array.create(12, uint32(0))

    mlen: int = array.length(message)
    adlen: int = array.length(ad)

    # Add nonce and key to state
    s[0:4] = bytes.to_uint32s_le(npub)
    s[4:12] = bytes.to_uint32s_le(key)
    s = gimli(s)

    s = process_ad(ad, adlen, s)
    s, ciphertext = process_msg(message, mlen, s)

    tag: bytes_t = squeeze_block(s)

    return (ciphertext, tag[:tlen])


@typechecked
def gimli_aead_decrypt(ciphertext: vlbytes_t,
                       ad: vlbytes_t,
                       tag: tag_t,
                       npub: nonce_t,
                       key: key_t) -> bytes_t:

    s: state_t = array.create(12, uint32(0))

    clen: int = array.length(ciphertext)
    adlen: int = array.length(ad)

    # Add nonce and key to state
    s[0:4] = bytes.to_uint32s_le(npub)
    s[4:12] = bytes.to_uint32s_le(key)
    s = gimli(s)

    s = process_ad(ad, adlen, s)
    s, message = process_ct(ciphertext, clen, s)

    tag_block: bytes_t = squeeze_block(s)

    # Compare tag
    for i in range(tlen):
        if tag[i] != tag_block[i]:
            fail("tag mismatch")

    return message
