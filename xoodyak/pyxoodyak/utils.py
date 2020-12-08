import random

def rand_bytes(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))