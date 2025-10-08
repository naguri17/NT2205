#!/usr/bin/env python3
import argparse
import binascii
import json
import sys
from pathlib import Path
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# ===============================
# Helpers
# ===============================

def hex_to_bytes(s: str) -> bytes:
    try:
        return binascii.unhexlify(s)
    except Exception:
        raise ValueError("Invalid hex string")

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def to_bytes_inline(data: str, encoding: str) -> bytes:
    enc = encoding.lower()
    if enc in ("utf8", "utf-8"):
        return data.encode("utf-8")
    elif enc == "hex":
        return hex_to_bytes(data)
    else:
        raise ValueError("encoding must be utf8 or hex for inline data")

def read_bytes_from_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_bytes_to_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)

def parse_inline_or_file(inline: str | None, file_path: str | None, encoding: str, what: str) -> bytes:
    if inline is not None and file_path is not None:
        raise ValueError(f"Provide either --{what} OR --{what}-file, not both.")
    if inline is None and file_path is None:
        return b""
    if inline is not None:
        return to_bytes_inline(inline, encoding)
    return read_bytes_from_file(file_path)

def parse_required_hex(name: str, value: str, expected_len: int | None = None) -> bytes:
    b = hex_to_bytes(value)
    if expected_len is not None and len(b) != expected_len:
        raise ValueError(f"{name} must be {expected_len} bytes (got {len(b)}).")
    return b

def default_tag_path(preferred: str | None) -> str | None:
    if not preferred:
        return None
    return preferred + ".tag"

# ===============================
# AEAD: ChaCha20-Poly1305
# ===============================

def encrypt_cc20p1305(pt: bytes, aad: bytes, key: bytes | None, nonce: bytes | None):
    key = key if key is not None else get_random_bytes(32)   # 32 bytes
    nonce = nonce if nonce is not None else get_random_bytes(12)  # 12 bytes
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return ct, tag, key, nonce

def decrypt_cc20p1305(ct: bytes, tag: bytes, aad: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)

# ===============================
# CLI
# ===============================

def main():
    p = argparse.ArgumentParser(
        description="ChaCha20-Poly1305 (AEAD) with AAD, file I/O, blob AAD||CT||TAG, and hex/utf8 inline modes"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Common options for enc/dec
    def add_common(sp):
        sp.add_argument("--key", help="Key (hex, 32 bytes). If omitted in encrypt, generated randomly.")
        sp.add_argument("--nonce", help="Nonce (hex, 12 bytes). If omitted in encrypt, generated randomly.")
        sp.add_argument("--aad", help="Additional Authenticated Data (inline; utf8/hex depending on --aad-enc)")
        sp.add_argument("--aad-file", help="AAD from file (raw binary). Mutually exclusive with --aad.")
        # accept both --aad-enc and the alias --add-enc (as you requested)
        sp.add_argument("--aad-enc", "--add-enc", dest="aad_enc",
                        choices=["utf8", "hex"], default="utf8",
                        help="Encoding for inline --aad (default: utf8)")

    # Encrypt
    enc = sub.add_parser("encrypt", help="Encrypt with ChaCha20-Poly1305")
    add_common(enc)
    enc.add_argument("--pt", help="Plaintext (inline; utf8/hex depending on --pt-enc)")
    enc.add_argument("--pt-file", help="Plaintext file (raw binary). Mutually exclusive with --pt.")
    enc.add_argument("--pt-enc", choices=["utf8", "hex"], default="utf8",
                     help="Encoding for inline --pt (default: utf8)")
    enc.add_argument("--out-ct", help="Write ciphertext to file (binary)")
    enc.add_argument("--out-tag", help="Write tag to file (binary). If omitted, defaults to <out-ct>.tag or <out-blob>.tag")
    enc.add_argument("--out-blob", help="Write single blob: AAD||CT||TAG (binary)")
    enc.add_argument("--out-meta", help="Write a JSON manifest with lengths and encodings")
    enc.add_argument("--print-hex", action="store_true",
                     help="Also print CT/KEY/NONCE/TAG in hex to stdout")

    # Decrypt
    dec = sub.add_parser("decrypt", help="Decrypt with ChaCha20-Poly1305")
    add_common(dec)
    dec.add_argument("--ct", help="Ciphertext (inline; hex/utf8 depending on --ct-enc). Usually hex.")
    dec.add_argument("--ct-file", help="Ciphertext file (raw binary). Mutually exclusive with --ct.")
    dec.add_argument("--ct-enc", choices=["hex", "utf8"], default="hex",
                     help="Encoding for inline --ct (default: hex)")
    dec.add_argument("--tag", help="Auth tag (hex) for inline CT mode")
    dec.add_argument("--tag-file", help="Auth tag file (raw binary). Required if --ct-file is used.")
    # Blob mode: read AAD||CT||TAG
    dec.add_argument("--ct-blob", help="Path to blob that contains AAD||CT||TAG (binary).")
    dec.add_argument("--aad-len", type=int, help="AAD length in bytes when using --ct-blob and no --aad/--aad-file")
    dec.add_argument("--out-pt", help="Write decrypted plaintext to file (binary)")
    dec.add_argument("--print-utf8", action="store_true",
                     help="Also print plaintext as UTF-8 to stdout (errors are ignored).")

    args = p.parse_args()

    try:
        if args.cmd == "encrypt":
            # Input PT
            if args.pt and args.pt_file:
                raise ValueError("Provide either --pt or --pt-file, not both.")
            pt = parse_inline_or_file(args.pt, args.pt_file, args.pt_enc, "pt")

            # AAD
            aad = parse_inline_or_file(args.aad, args.aad_file, args.aad_enc, "aad")

            # Key & Nonce
            key_b = parse_required_hex("key", args.key, 32) if args.key else None
            nonce_b = parse_required_hex("nonce", args.nonce, 12) if args.nonce else None

            ct, tag, key_out, nonce_out = encrypt_cc20p1305(pt, aad, key_b, nonce_b)

            # Files: CT / TAG
            tag_written = False
            if args.out_ct:
                write_bytes_to_file(args.out_ct, ct)
                if not args.out_tag:
                    args.out_tag = default_tag_path(args.out_ct)
                if args.out_tag:
                    write_bytes_to_file(args.out_tag, tag)
                    tag_written = True

            # Blob: AAD||CT||TAG
            if args.out_blob:
                blob = aad + ct + tag
                write_bytes_to_file(args.out_blob, blob)
                if not args.out_tag and not tag_written:
                    args.out_tag = default_tag_path(args.out_blob)
                if args.out_tag and not tag_written:
                    write_bytes_to_file(args.out_tag, tag)
                    tag_written = True

            # META
            if args.out_meta:
                meta = {
                    "mode": "encrypt",
                    "aad_enc": args.aad_enc,
                    "pt_enc": args.pt_enc,
                    "lengths": {"aad": len(aad), "ct": len(ct), "tag": len(tag)},
                    "key_hex": bytes_to_hex(key_out),
                    "nonce_hex": bytes_to_hex(nonce_out),
                    "outputs": {
                        "out_ct": args.out_ct or None,
                        "out_tag": args.out_tag or None,
                        "out_blob": args.out_blob or None
                    }
                }
                write_bytes_to_file(args.out_meta, json.dumps(meta, indent=2).encode("utf-8"))

            # Stdout hex summary
            if args.print_hex or (not args.out_ct and not args.out_blob):
                print("Ciphertext (hex):", bytes_to_hex(ct))
                print("Tag        (hex):", bytes_to_hex(tag))
                print("Key        (hex):", bytes_to_hex(key_out))
                print("Nonce      (hex):", bytes_to_hex(nonce_out))
                if args.out_blob:
                    print(f"Wrote blob (AAD||CT||TAG): {args.out_blob}  "
                          f"(lens: aad={len(aad)}, ct={len(ct)}, tag=16)")

        else:  # decrypt
            if not args.key or not args.nonce:
                raise ValueError("--key and --nonce (both hex) are required for decrypt.")
            key_b = parse_required_hex("key", args.key, 32)
            nonce_b = parse_required_hex("nonce", args.nonce, 12)

            # Blob mode?
            if args.ct_blob:
                blob = read_bytes_from_file(args.ct_blob)
                # Determine AAD
                aad = parse_inline_or_file(args.aad, args.aad_file, args.aad_enc, "aad")
                if aad:
                    if not blob.startswith(aad):
                        raise ValueError("Blob does not start with provided AAD bytes.")
                    rest = blob[len(aad):]
                else:
                    if args.aad_len is None:
                        raise ValueError("Provide --aad/--aad-file or --aad-len when using --ct-blob.")
                    if args.aad_len < 0 or args.aad_len > len(blob):
                        raise ValueError("Invalid --aad-len relative to blob size.")
                    aad = blob[:args.aad_len]
                    rest = blob[args.aad_len:]
                if len(rest) < 16:
                    raise ValueError("Blob too short: missing 16-byte tag.")
                ct = rest[:-16]
                tag = rest[-16:]

            else:
                # Traditional CT+TAG inputs
                if args.ct and args.ct_file:
                    raise ValueError("Provide either --ct or --ct-file, not both.")
                ct = parse_inline_or_file(args.ct, args.ct_file, args.ct_enc, "ct")

                if args.tag and args.tag_file:
                    raise ValueError("Provide either --tag or --tag-file, not both.")
                if args.ct_file and not (args.tag or args.tag_file):
                    raise ValueError("For --ct-file, you must provide --tag or --tag-file.")
                tag = (hex_to_bytes(args.tag) if args.tag is not None
                       else read_bytes_from_file(args.tag_file) if args.tag_file is not None
                       else b"")

                aad = parse_inline_or_file(args.aad, args.aad_file, args.aad_enc, "aad")

            pt = decrypt_cc20p1305(ct, tag, aad, key_b, nonce_b)

            if args.out_pt:
                write_bytes_to_file(args.out_pt, pt)

            if args.print_utf8 and not args.out_pt:
                try:
                    print("Plaintext (utf8):", pt.decode("utf-8"))
                except UnicodeDecodeError:
                    print("Plaintext (utf8): [decode error] — output is binary; use --out-pt to save.")
            elif not args.out_pt:
                print("Plaintext (hex):", bytes_to_hex(pt))

    except Exception as e:
        print("Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
