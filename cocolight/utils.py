import random

def rand_bytes(num_bytes: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(num_bytes))
    
def bytes_to_words(x: bytes, width, byteorder):
    assert width % 8 == 0
    word_bytes = width // 8
    remain = len(x) % word_bytes
    if remain:
        x += b'\0'*(word_bytes - remain)
    ret = [int.from_bytes(x[i:i + word_bytes], byteorder)
           for i in range(0, len(x), word_bytes)
           ]
    # print(f'bytes_to_words: {x.hex()} -> {[hex(r) for r in  ret]}')
    return ret
