# RSA + OpenSSL — Detailed Notes and Checklist

## 1. Quick Facts about RSA

- **RSA** is an asymmetric cryptographic algorithm used for encryption, digital signatures, and key exchange.  
- Security is based on the difficulty of **factoring large integers** (product of two primes).  
- Common key sizes: **2048 bits** (standard), **3072 bits**, or **4096 bits** (high security).  
- RSA supports two main use cases:
  - **Encryption/Decryption**
  - **Signing/Verification**

---

## 2. High-Level Recommendations

- Use **at least 2048-bit** keys; prefer 3072 or 4096 for new systems.
- For new designs, use **hybrid encryption** (RSA + AES).
- Never use RSA directly on large files — only encrypt symmetric keys.
- Use **PKCS#1 v2.2 (OAEP)** for encryption padding.
- Use **PSS** padding for digital signatures.

---

## 3. OpenSSL: Basic Commands & Examples

### a) Generate RSA Key Pair

```bash
# Generate private key (2048-bit)
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

### b) View RSA Key Details

```bash
openssl rsa -in private.pem -text -noout
openssl rsa -pubin -in public.pem -text -noout
```

### c) Encrypt and Decrypt (RSA-OAEP)

```bash
# Encrypt with public key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in plaintext.txt -out ciphertext.bin -pkeyopt rsa_padding_mode:oaep

# Decrypt with private key
openssl pkeyutl -decrypt -inkey private.pem -in ciphertext.bin -out recovered.txt -pkeyopt rsa_padding_mode:oaep
```

### d) Sign and Verify (RSA-PSS)

```bash
# Create signature
openssl dgst -sha256 -sign private.pem -out signature.bin plaintext.txt

# Verify signature
openssl dgst -sha256 -verify public.pem -signature signature.bin plaintext.txt
```

---

## 4. Hybrid Encryption (Recommended)

RSA is typically used to encrypt an AES key, then AES encrypts the file.

```bash
# Generate random AES key
openssl rand -out aes.key 32

# Encrypt AES key with RSA public key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in aes.key -out aes.key.enc -pkeyopt rsa_padding_mode:oaep

# Decrypt AES key with private key
openssl pkeyutl -decrypt -inkey private.pem -in aes.key.enc -out aes.key -pkeyopt rsa_padding_mode:oaep

# Use AES key for file encryption
openssl enc -aes-256-cbc -in data.txt -out data.enc -pass file:./aes.key
openssl enc -aes-256-cbc -d -in data.enc -out data.txt -pass file:./aes.key
```

---

## 5. Key Conversion & Formats

```bash
# Convert PEM to DER (binary format)
openssl rsa -in private.pem -outform DER -out private.der

# Convert DER to PEM
openssl rsa -inform DER -in private.der -out private.pem

# Extract public key from certificate
openssl x509 -in cert.pem -pubkey -noout > public.pem
```

---

## 6. Common Troubleshooting

| Issue | Possible Cause | Fix |
|--------|----------------|------|
| `RSA routines:padding check failed` | Wrong key or padding mode | Ensure both sides use OAEP or PSS |
| `no start line` | Missing PEM header/footer | Add `-----BEGIN/END RSA KEY-----` lines |
| Cannot decrypt large file | RSA not for large data | Use hybrid encryption (AES + RSA) |
| Mismatched key type | Wrong key pair | Match correct private/public key |

---

## 7. RSA Implementation Checklist

| Step | Description | Command/Note |
|------|--------------|--------------|
| 1 | Generate private key | `openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048` |
| 2 | Extract public key | `openssl rsa -in private.pem -pubout -out public.pem` |
| 3 | Encrypt small file/key | `openssl pkeyutl -encrypt -pubin -inkey public.pem -in key.bin -out key.enc -pkeyopt rsa_padding_mode:oaep` |
| 4 | Decrypt | `openssl pkeyutl -decrypt -inkey private.pem -in key.enc -out key.bin -pkeyopt rsa_padding_mode:oaep` |
| 5 | Sign file | `openssl dgst -sha256 -sign private.pem -out sig.bin file.txt` |
| 6 | Verify signature | `openssl dgst -sha256 -verify public.pem -signature sig.bin file.txt` |
| 7 | Export to DER | `openssl rsa -in private.pem -outform DER -out private.der` |
| 8 | Backup securely | Store keys offline, encrypted, and access-controlled |

---

## 8. Quick Cheat Sheet

```bash
# Generate keys
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt/Decrypt
openssl pkeyutl -encrypt -pubin -inkey public.pem -in msg.txt -out msg.enc -pkeyopt rsa_padding_mode:oaep
openssl pkeyutl -decrypt -inkey private.pem -in msg.enc -out msg.txt -pkeyopt rsa_padding_mode:oaep

# Sign/Verify
openssl dgst -sha256 -sign private.pem -out sig.bin msg.txt
openssl dgst -sha256 -verify public.pem -signature sig.bin msg.txt
```

---

## 9. References

- PKCS#1 v2.2 (RFC 8017)
- NIST SP 800-56B (Key establishment)
- OpenSSL Documentation (`man genpkey`, `man pkeyutl`, `man dgst`)
- OWASP Cryptographic Storage Cheat Sheet
