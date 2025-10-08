def ksa(key: bytes) -> list[int]:
    """
    RC4 Key Scheduling Algorithm (KSA)
    :param key: key bytes (ví dụ b"Key")
    :return: hoán vị S (list 0..255 sau khi trộn)
    """
    L = len(key)
    if L == 0:
        raise ValueError("Key length must be > 0")

    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % L]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S


# --- Ví dụ sử dụng ---
key = b"Test"  # input (bytes)
S = ksa(key)
a = 5
b = "test"
c = b"abc"

for b in c:
    print(b)



# print("Key:", key)
# print("S (first 20 elements):", S[:20])  # in ngắn gọn
# print("Length of S:", len(S))
