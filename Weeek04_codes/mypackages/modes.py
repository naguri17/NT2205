# -*- coding: utf-8 -*-
import sys, os
DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)))
from .DES import DES
############# Padding to plaintex
# Padding functions for binary strings
@staticmethod
def pkcs7_pad_binary(binary_str, block_size=64):
# Byte alignment
    while len(binary_str) % 8 != 0:
        binary_str += '0'

    # Calculate the padding length
    padding_length = block_size - (len(binary_str) % block_size)
    padding_byte = format(padding_length // 8, '08b')  # Convert to 8-bit binary
    padding = padding_byte * (padding_length // 8)
    return binary_str + padding
@staticmethod
def pkcs7_unpad_binary(padded_binary_str):
# Get the last 8 bits to determine the padding length
    padding_byte = padded_binary_str[-8:]
    padding_length = int(padding_byte, 2) * 8  # Convert to number of bits
    return padded_binary_str[:-padding_length]

###############Padding bytes infomm 0x0j where j is number of bytes needed
def pkcs7_pad(plaintext, block_size=64):
    """Pad the plaintext using PKCS#7 padding."""
    # Calculate the padding length in bytes
    padding_length_bytes = block_size // 8 - (len(plaintext) // 8) % (block_size // 8)
    
    # Convert the padding length to its binary representation
    padding_byte = format(padding_length_bytes, '08b')
    
    # Repeat the padding byte for the required number of times
    padding = padding_byte * padding_length_bytes
    
    print("Padded text length:", len(plaintext + padding))
    return plaintext + padding

def pkcs7_unpad(padded_text):
    """Remove the PKCS#7 padding from the text."""
    # Extract the last 8 bits to determine the padding length in bytes
    padding_byte = padded_text[-8:]
    padding_length_bytes = int(padding_byte, 2)
    
    # Calculate the padding length in bits
    padding_length_bits = padding_length_bytes * 8
    
    # Return the text without padding
    return padded_text[:-padding_length_bits]



class DES_ECB:
    def __init__(self, key):
        self.des = DES(key)
    def ecb_instance(key):
        return DES_ECB(key)
    
    def encrypt(self, plaintext):
        # Ensure the plaintext is a multiple of 64 bits
        plaintext=pkcs7_pad_binary(plaintext)
        plaintext=pkcs7_pad(plaintext, block_size=64)

        ciphertext = ""
        # Encrypt each 64-bit block of plaintext
        for i in range(0, len(plaintext), 64):
            block = plaintext[i:i+64]
            print("block:", len(block), block)
            ciphertext += self.des.encrypt(block)
        return ciphertext

    def decrypt(self, ciphertext):
        # Ensure the ciphertext is a multiple of 64 bits
        if len(ciphertext) % 64 != 0:
            raise ValueError("Ciphertext length must be a multiple of 64 bits in ECB mode.")
        padded_text = ""
        # Decrypt each 64-bit block of ciphertext
        for i in range(0, len(ciphertext), 64):
            block = ciphertext[i:i+64]
            padded_text += self.des.decrypt(block)
        padded_text = pkcs7_unpad(padded_text)
        binarytext=pkcs7_unpad_binary(padded_text)
        return binarytext

class DES_CBC:
    def __init__(self, key, iv):
        self.des = DES(key)
        self.iv = iv  # Initialization Vector (IV) should be 64 bits
    def cbc_instance(key, iv):
        return DES_CBC(key, iv)
    def encrypt(self, plaintext):
        # Ensure the plaintext is a multiple of 64 bits
        if len(plaintext) % 64 != 0:
            raise ValueError("Plaintext length must be a multiple of 64 bits in CBC mode.")

        ciphertext = ""
        previous_block = self.iv
        # Encrypt each 64-bit block of plaintext
        for i in range(0, len(plaintext), 64):
            block = plaintext[i:i+64]
            # XOR the block with the previous ciphertext block (or IV for the first block)
            block_to_encrypt = self.xor(block, previous_block)
            encrypted_block = self.des.encrypt(block_to_encrypt)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return ciphertext
    def decrypt(self, ciphertext):
        # Ensure the ciphertext is a multiple of 64 bits
        if len(ciphertext) % 64 != 0:
            raise ValueError("Ciphertext length must be a multiple of 64 bits in CBC mode.")

        plaintext = ""
        previous_block = self.iv
        # Decrypt each 64-bit block of ciphertext
        for i in range(0, len(ciphertext), 64):
            block = ciphertext[i:i+64]
            decrypted_block = self.des.decrypt(block)
            # XOR the decrypted block with the previous ciphertext block (or IV for the first block)
            plaintext_block = self.xor(decrypted_block, previous_block)
            plaintext += plaintext_block
            previous_block = block

        return plaintext

    def xor(self, block1, block2):
        return ''.join(['1' if b1 != b2 else '0' for b1, b2 in zip(block1, block2)])
