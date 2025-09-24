# trivium.py - small Trivium implementation (80-bit key, 80-bit IV)
def trivium_keystream(key80: bytes, iv80: bytes, nbits: int):
    assert len(key80) == 10 and len(iv80) == 10  # 80 bits each
    # Initialize state (288 bits): s1..s93, s94..s177, s178..s288
    s = [0]*288
    # load key into s[0..79]
    keybits = [(key80[i//8] >> (i%8)) & 1 for i in range(80)]
    ivbits  = [(iv80[i//8] >> (i%8)) & 1 for i in range(80)]
    for i in range(80):
        s[i] = keybits[i]
    for i in range(80):
        s[93 + i] = ivbits[i]
    # remaining
    s[285] = s[286] = s[287] = 1  # last three bits set to 1
    # 4*288 initialization clocks
    for _ in range(4*288):
        t1 = s[65] ^ (s[90] & s[91]) ^ s[92] ^ s[170]
        t2 = s[161] ^ (s[174] & s[175]) ^ s[176] ^ s[263]
        t3 = s[242] ^ (s[285] & s[286]) ^ s[287] ^ s[68]
        # shift
        s = [t3] + s[:92] + [t1] + s[93:176] + [t2] + s[177:287]
    # now produce keystream bits
    for _ in range(nbits):
        t1 = s[65] ^ (s[90] & s[91]) ^ s[92] ^ s[170]
        t2 = s[161] ^ (s[174] & s[175]) ^ s[176] ^ s[263]
        t3 = s[242] ^ (s[285] & s[286]) ^ s[287] ^ s[68]
        z = t1 ^ t2 ^ t3
        yield z
        s = [t3] + s[:92] + [t1] + s[93:176] + [t2] + s[177:287]

def trivium_encrypt(key80: bytes, iv80: bytes, plaintext: bytes) -> bytes:
    nbits = len(plaintext)*8
    ks = trivium_keystream(key80, iv80, nbits)
    out = bytearray()
    bitbuf = 0
    bitcnt = 0
    for b in plaintext:
        by = 0
        for i in range(8):
            kbit = next(ks)
            pbit = (b >> i) & 1
            by |= ((pbit ^ kbit) << i)
        out.append(by)
    return bytes(out)

# Usage:
# key = b'\x01'*10
# iv  = b'\x00'*10
# ct = trivium_encrypt(key, iv, b"hello")
# pt = trivium_encrypt(key, iv, ct)
