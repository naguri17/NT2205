# AES + OpenSSL — Detailed Notes and Checklist

## 1. Quick Facts about AES

- AES is a symmetric block cipher with 128-bit block size and three key sizes: **AES-128, AES-192, AES-256**.
- AES itself is a confidentiality primitive only; **modes of operation** provide how to encrypt longer messages (ECB, CBC, CFB, OFB, CTR, etc.). Use of authenticated modes (AEAD) is recommended when possible.

---

## 2. High-Level Recommendations (Best Practice)

- **Never use ECB** for real data. Prefer AEAD (AES-GCM / AES-CCM).
- **IV / Nonce rules**:
  - CBC: IV must be random and unique per encryption.
  - CTR/GCM: Nonce must be unique; reuse is catastrophic.
- **Key sizes**: AES-256 for long-term security, AES-128 still safe.
- **Use a KDF** like PBKDF2, Argon2, or scrypt. Avoid raw passwords as keys.

---

## 3. OpenSSL: Basic Commands & Examples

### a) Generate Random Key and IV

```bash
openssl rand -hex 16   # AES-128 key
openssl rand -hex 32   # AES-256 key
openssl rand -hex 16   # IV
```

### b) Encrypt/Decrypt with Explicit Key and IV

```bash
# Encrypt
openssl enc -aes-256-cbc -in plaintext.txt -out ciphertext.bin   -K <hexkey> -iv <hexiv>

# Decrypt
openssl enc -aes-256-cbc -d -in ciphertext.bin -out recovered.txt   -K <hexkey> -iv <hexiv>
```

### c) Password-Based Encryption (Recommended)

```bash
# Encrypt
openssl enc -aes-256-cbc -pbkdf2 -salt -in plaintext.txt -out ciphertext.bin -pass pass:"myPassword"

# Decrypt
openssl enc -aes-256-cbc -pbkdf2 -d -in ciphertext.bin -out recovered.txt -pass pass:"myPassword"
```

### d) AES-GCM (Authenticated Encryption)

```bash
# Encrypt
openssl enc -aes-256-gcm -in plaintext.txt -out ciphertext.bin  -K <hexkey> -iv <hexiv> -nosalt

# Decrypt
openssl enc -aes-256-gcm -d -in ciphertext.bin -out recovered.txt  -K <hexkey> -iv <hexiv> -nosalt
```

---

## 4. Verification and Debugging

- Confirm key/IV lengths: 16 bytes (AES-128), 32 bytes (AES-256).
- If decryption fails: check hex format, mode, IV correctness, and AEAD tag.
- Use `-p` flag to print derived key and IV.

---

## 5. Common Pitfalls

- **IV reuse**: never reuse IV/nonce with same key.
- **No authentication**: CBC/CTR without HMAC/AEAD = insecure.
- **Weak derivation**: always use `-pbkdf2` with OpenSSL.

---

## 6. AES Implementation Checklist

| Step | Description | Command/Note |
|------|--------------|--------------|
| 1 | Choose AES mode | Prefer AES-GCM |
| 2 | Generate key | `openssl rand -hex 32` |
| 3 | Generate IV | `openssl rand -hex 16` |
| 4 | Encrypt | `openssl enc -aes-256-cbc -in in.txt -out out.bin -K <key> -iv <iv>` |
| 5 | Store metadata | Save IV + ciphertext |
| 6 | Decrypt | `openssl enc -aes-256-cbc -d -in out.bin -out out.txt -K <key> -iv <iv>` |
| 7 | Validate | Compare hashes of plaintexts |
| 8 | Rotate keys | Schedule regular rotation |

---

## 7. Quick Cheat Sheet

```bash
# Key generation
openssl rand -hex 16   # AES-128
openssl rand -hex 32   # AES-256

# Encrypt with key/iv
openssl enc -aes-256-cbc -in plain.txt -out cipher.bin -K <hexkey> -iv <hexiv>

# Password-based encryption
openssl enc -aes-256-cbc -pbkdf2 -salt -in plain.txt -out cipher.bin -pass pass:"secret"

# Decrypt
openssl enc -aes-256-cbc -d -in cipher.bin -out plain.txt -K <hexkey> -iv <hexiv>
```

---

## 8. References

- NIST FIPS 197 (AES standard)
- NIST SP 800-38A (Modes of operation)
- OpenSSL man pages (`man enc`)
- OWASP Cryptographic Storage Cheat Sheet
