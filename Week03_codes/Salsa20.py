# salsa20.py - simple Salsa20/20 block + encrypt (64-byte blocks)
import struct

def rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def salsa20_block(key32: bytes, counter: int, nonce8: bytes) -> bytes:
    # key32: 32 bytes (256-bit key)
    # counter: 64-bit block counter (as int)
    # nonce8: 8 bytes nonce (64-bit) for original Salsa20
    assert len(key32) == 32
    assert len(nonce8) == 8
    def u32(b): return struct.unpack("<I", b)[0]
    constants = b"expand 32-byte k"
    state = [
        u32(constants[0:4]),
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(constants[4:8]),
        u32(nonce8[0:4]), u32(nonce8[4:8]),
        counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF,
        u32(constants[8:12]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        u32(constants[12:16])
    ]
    x = state.copy()
    for _ in range(10):  # 20 rounds = 10 double-rounds
        # column round
        x[4] ^= rotl32((x[0] + x[12]) & 0xFFFFFFFF, 7)
        x[8] ^= rotl32((x[4] + x[0]) & 0xFFFFFFFF, 9)
        x[12] ^= rotl32((x[8] + x[4]) & 0xFFFFFFFF, 13)
        x[0] ^= rotl32((x[12] + x[8]) & 0xFFFFFFFF, 18)

        x[9] ^= rotl32((x[5] + x[1]) & 0xFFFFFFFF, 7)
        x[13] ^= rotl32((x[9] + x[5]) & 0xFFFFFFFF, 9)
        x[1] ^= rotl32((x[13] + x[9]) & 0xFFFFFFFF, 13)
        x[5] ^= rotl32((x[1] + x[13]) & 0xFFFFFFFF, 18)

        x[14] ^= rotl32((x[10] + x[6]) & 0xFFFFFFFF, 7)
        x[2] ^= rotl32((x[14] + x[10]) & 0xFFFFFFFF, 9)
        x[6] ^= rotl32((x[2] + x[14]) & 0xFFFFFFFF, 13)
        x[10] ^= rotl32((x[6] + x[2]) & 0xFFFFFFFF, 18)

        x[3] ^= rotl32((x[15] + x[11]) & 0xFFFFFFFF, 7)
        x[7] ^= rotl32((x[3] + x[15]) & 0xFFFFFFFF, 9)
        x[11] ^= rotl32((x[7] + x[3]) & 0xFFFFFFFF, 13)
        x[15] ^= rotl32((x[11] + x[7]) & 0xFFFFFFFF, 18)

        # row round
        x[1] ^= rotl32((x[0] + x[3]) & 0xFFFFFFFF, 7)
        x[2] ^= rotl32((x[1] + x[0]) & 0xFFFFFFFF, 9)
        x[3] ^= rotl32((x[2] + x[1]) & 0xFFFFFFFF, 13)
        x[0] ^= rotl32((x[3] + x[2]) & 0xFFFFFFFF, 18)

        x[6] ^= rotl32((x[5] + x[4]) & 0xFFFFFFFF, 7)
        x[7] ^= rotl32((x[6] + x[5]) & 0xFFFFFFFF, 9)
        x[4] ^= rotl32((x[7] + x[6]) & 0xFFFFFFFF, 13)
        x[5] ^= rotl32((x[4] + x[7]) & 0xFFFFFFFF, 18)

        x[11] ^= rotl32((x[10] + x[9]) & 0xFFFFFFFF, 7)
        x[8] ^= rotl32((x[11] + x[10]) & 0xFFFFFFFF, 9)
        x[9] ^= rotl32((x[8] + x[11]) & 0xFFFFFFFF, 13)
        x[10] ^= rotl32((x[9] + x[8]) & 0xFFFFFFFF, 18)

        x[12] ^= rotl32((x[15] + x[14]) & 0xFFFFFFFF, 7)
        x[13] ^= rotl32((x[12] + x[15]) & 0xFFFFFFFF, 9)
        x[14] ^= rotl32((x[13] + x[12]) & 0xFFFFFFFF, 13)
        x[15] ^= rotl32((x[14] + x[13]) & 0xFFFFFFFF, 18)

    out = b"".join(struct.pack("<I", (x[i] + state[i]) & 0xFFFFFFFF) for i in range(16))
    return out  # 64 bytes

def salsa20_encrypt(key32: bytes, nonce8: bytes, plaintext: bytes, initial_counter=0) -> bytes:
    import struct
    assert len(key32) == 32 and len(nonce8) == 8
    out = bytearray()
    counter = initial_counter
    pos = 0
    while pos < len(plaintext):
        block = salsa20_block(key32, counter, nonce8)
        chunk = plaintext[pos:pos+64]
        for i, b in enumerate(chunk):
            out.append(b ^ block[i])
        pos += len(chunk)
        counter += 1
    return bytes(out)

# Usage:
# key = b'\x00'*32
# nonce = b'\x00'*8
# ct = salsa20_encrypt(key, nonce, b"hello world")
# pt = salsa20_encrypt(key, nonce, ct)  # recovers
