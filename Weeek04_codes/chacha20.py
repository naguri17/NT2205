import argparse
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import binascii
import sys
import os

# ===============================
# Helper functions
# ===============================

def to_bytes(data, encoding="utf-8"):
    if encoding == "utf-8":
        return data.encode("utf-8")
    elif encoding == "hex":
        return binascii.unhexlify(data)
    elif encoding == "bin":
        return data if isinstance(data, bytes) else bytes(data)
    else:
        raise ValueError("Unsupported encoding")

def from_bytes(data_bytes, encoding="utf-8"):
    if encoding == "utf-8":
        return data_bytes.decode("utf-8")
    elif encoding == "hex":
        return binascii.hexlify(data_bytes).decode()
    elif encoding == "bin":
        return data_bytes
    else:
        raise ValueError("Unsupported encoding")

def read_input(input_arg, input_file, encoding):
    if input_file:
        mode = 'rb' if encoding == "bin" else 'r'
        with open(input_file, mode) as f:
            data = f.read()
    else:
        data = input_arg
    return data

def write_output(output_data, output_file, encoding):
    if output_file:
        mode = 'wb' if encoding == "bin" else 'w'
        with open(output_file, mode) as f:
            f.write(output_data)
    else:
        if encoding == "bin":
            print(binascii.hexlify(output_data).decode())
        else:
            print(output_data)

# ===============================
# ChaCha20 functions
# ===============================

def encrypt_chacha20(plaintext, key=None, nonce=None, encoding="utf-8"):
    data_bytes = to_bytes(plaintext, encoding)

    if key is None:
        key = get_random_bytes(32)
    else:
        key = to_bytes(key, "hex")  # key must be hex

    if nonce is None:
        nonce = get_random_bytes(8)
    else:
        nonce = to_bytes(nonce, "hex")  # nonce must be hex

    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(data_bytes)

    return ciphertext, key, nonce

def decrypt_chacha20(ciphertext, key, nonce, encoding="utf-8"):
    key = to_bytes(key, "hex")
    nonce = to_bytes(nonce, "hex")
    ciphertext_bytes = to_bytes(ciphertext, encoding)

    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)

    return from_bytes(decrypted_bytes, encoding)

# ===============================
# CLI
# ===============================

def main():
    parser = argparse.ArgumentParser(description="ChaCha20 Encryption/Decryption CLI")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("input", nargs="?", help="Input data (plaintext or ciphertext)")
    parser.add_argument("--input-file", help="Path to input file")
    parser.add_argument("--output-file", help="Path to output file")
    parser.add_argument(
        "--encoding",
        choices=["utf8", "hex", "bin"],
        default="utf8",
        help="Input/output encoding (utf8, hex, bin)"
    )
    parser.add_argument("--key", help="Hex key (32 bytes, optional for encrypt)")
    parser.add_argument("--nonce", help="Hex nonce (8 bytes, optional for encrypt)")

    args = parser.parse_args()

    # Normalize encoding
    encoding = args.encoding.lower()
    if encoding == "utf8":
        encoding = "utf-8"

    try:
        input_data = read_input(args.input, args.input_file, encoding)

        if args.mode == "encrypt":
            ciphertext, key, nonce = encrypt_chacha20(input_data, args.key, args.nonce, encoding)
            # Write ciphertext to file or stdout
            write_output(ciphertext, args.output_file, "bin")
            # Always print key/nonce
            print("Key (hex):", binascii.hexlify(key).decode())
            print("Nonce (hex):", binascii.hexlify(nonce).decode())

        else:  # decrypt
            plaintext = decrypt_chacha20(input_data, args.key, args.nonce, encoding)
            write_output(plaintext, args.output_file, encoding)

    except Exception as e:
        print("Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
