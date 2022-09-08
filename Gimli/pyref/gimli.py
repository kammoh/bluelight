#!/usr/bin/python3

from hacspec.speclib import *

state_t = array_t(uint32_t, 12)

@typechecked
def gimli_round(s: state_t, r: int) -> state_t:
    for col in range(4):
        x : uint32_t = uintn.rotate_left(s[col], 24)
        y : uint32_t = uintn.rotate_left(s[col + 4], 9)
        z : uint32_t = s[col + 8]

        s[col + 8] = x ^ (z << 1) ^ ((y & z) << 2)
        s[col + 4] = y ^ x ^ ((x | z) << 1)
        s[col] = z ^ y ^ ((x & y) << 3)

    if ((r & 3) == 0):
        s[0], s[1] = s[1], s[0]
        s[2], s[3] = s[3], s[2]

    if ((r & 3) == 2):
        s[0], s[2] = s[2], s[0]
        s[1], s[3] = s[3], s[1]

    if ((r & 3) == 0):
        s[0] = s[0] ^ (uint32(0x9e377900) | uint32(r))

    return s

@typechecked
def gimli(s: state_t) -> state_t:
    tmp_state : state_t = array.copy(s)
    for rnd in range(24):
        tmp_state = gimli_round(tmp_state, 24 - rnd)

    return tmp_state
