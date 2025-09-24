# chacha20.py - ChaCha20 block function and encrypt
import struct

def chacha20_quarter_round(a,b,c,d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = ((d << 16) & 0xFFFFFFFF) | (d >> 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = ((b << 12) & 0xFFFFFFFF) | (b >> 20)
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = ((d << 8) & 0xFFFFFFFF) | (d >> 24)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = ((b << 7) & 0xFFFFFFFF) | (b >> 25)
    return a,b,c,d

def chacha20_block(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    assert len(key32) == 32 and len(nonce12) == 12
    def u32(b): return struct.unpack("<I", b)[0]
    constants = (b"expa", b"nd 3", b"2-by", b"te k")
    state = [
        u32(b"expa"), u32(b"nd 3"), u32(b"2-by"), u32(b"te k"),
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        u32(nonce12[0:4]), u32(nonce12[4:8])  # note: RFC uses 12-byte nonce, last word from nonce[8:12]
    ]
    # RFC 8439 uses counter (32-bit) + nonce 96-bit; adjust mapping:
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32(key32[0:4]), u32(key32[4:8]), u32(key32[8:12]), u32(key32[12:16]),
        u32(key32[16:20]), u32(key32[20:24]), u32(key32[24:28]), u32(key32[28:32]),
        counter & 0xFFFFFFFF,
        u32(nonce12[0:4]), u32(nonce12[4:8]), u32(nonce12[8:12])
    ]
    x = state.copy()
    for _ in range(10):  # 20 rounds
        # column rounds
        x[0],x[4],x[8],x[12] = chacha20_quarter_round(x[0],x[4],x[8],x[12])
        x[1],x[5],x[9],x[13] = chacha20_quarter_round(x[1],x[5],x[9],x[13])
        x[2],x[6],x[10],x[14] = chacha20_quarter_round(x[2],x[6],x[10],x[14])
        x[3],x[7],x[11],x[15] = chacha20_quarter_round(x[3],x[7],x[11],x[15])
        # diagonal rounds
        x[0],x[5],x[10],x[15] = chacha20_quarter_round(x[0],x[5],x[10],x[15])
        x[1],x[6],x[11],x[12] = chacha20_quarter_round(x[1],x[6],x[11],x[12])
        x[2],x[7],x[8],x[13] = chacha20_quarter_round(x[2],x[7],x[8],x[13])
        x[3],x[4],x[9],x[14] = chacha20_quarter_round(x[3],x[4],x[9],x[14])
    out = b"".join(struct.pack("<I", (x[i] + state[i]) & 0xFFFFFFFF) for i in range(16))
    return out  # 64 bytes

def chacha20_encrypt(key32: bytes, nonce12: bytes, plaintext: bytes, initial_counter=1) -> bytes:
    assert len(key32) == 32 and len(nonce12) == 12
    pos = 0
    out = bytearray()
    counter = initial_counter
    while pos < len(plaintext):
        block = chacha20_block(key32, counter, nonce12)
        chunk = plaintext[pos:pos+64]
        for i, b in enumerate(chunk):
            out.append(b ^ block[i])
        pos += len(chunk)
        counter = (counter + 1) & 0xffffffff
    return bytes(out)

# Usage:
# key = b'\x00'*32
# nonce = b'\x00'*12
# ct = chacha20_encrypt(key, nonce, b"hello world")
# pt = chacha20_encrypt(key, nonce, ct)
