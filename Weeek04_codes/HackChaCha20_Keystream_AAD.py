#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Hackstreamcipher_rev_suffix.py
# Keystream extractor for ChaCha20/Poly1305 demos (NO AAD, suffix-aligned).
# - Known pair:  if len(blob) >= |PT|+16, strip 16-byte tag; then take CT_tail = last |PT|.
#                KS = PT XOR CT_tail.
# - Victims:     if len(victim) >= |KS|+16, strip 16-byte tag; then decrypt tail with KS_tail.
# - Outputs victim plaintext as CT-length buffer with only the recovered tail filled (head zeros).
#
# This is classroom tooling to illustrate stream-cipher keystream reuse pitfalls with AEAD.
# It intentionally ignores AAD and aligns exclusively from the right.

import argparse
import sys
from pathlib import Path

TAG_LEN = 16

# ---------- IO helpers ----------

def readb(p: str | Path) -> bytes:
    return Path(p).read_bytes()

def writeb(p: str | Path, data: bytes) -> None:
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

# ---------- Core logic ----------

def _maybe_strip_tag_for_known(blob: bytes, pt_len: int) -> tuple[bytes, bool]:
    """
    For the known pair: if blob is large enough to plausibly be CT||TAG (>= |PT|+16),
    strip a 16-byte tag from the end; otherwise keep as-is.
    """
    if len(blob) >= pt_len + TAG_LEN:
        return blob[:-TAG_LEN], True
    return blob, False

def _maybe_strip_tag_for_victim(blob: bytes, ks_len: int) -> tuple[bytes, bool]:
    """
    For victim blobs: if blob is large enough relative to KS (>= |KS|+16),
    strip a 16-byte tag from the end; otherwise keep as-is.
    """
    if len(blob) >= ks_len + TAG_LEN:
        return blob[:-TAG_LEN], True
    return blob, False

def recover_keystream_suffix(known_pt: bytes, blob: bytes) -> tuple[bytes, int, bool]:
    """
    Recover keystream segment from a known PT and a ciphertext blob.

    Steps:
      1) If len(blob) >= |PT|+16, strip 16-byte tag.
      2) Ensure CT region is at least |PT|.
      3) Take the last |PT| bytes as CT_slice and XOR with PT.

    Returns:
      (ks_segment, suffix_offset_in_ct_region, tag_stripped)
    """
    ct_region, tag_stripped = _maybe_strip_tag_for_known(blob, len(known_pt))
    if len(ct_region) < len(known_pt):
        raise ValueError(f"CT region shorter than PT for suffix alignment: "
                         f"PT={len(known_pt)} CT_region={len(ct_region)}")
    start = len(ct_region) - len(known_pt)
    ct_slice = ct_region[-len(known_pt):]
    ks = bytes(p ^ c for p, c in zip(known_pt, ct_slice))
    return ks, start, tag_stripped

def decrypt_victim_suffix(victim_blob: bytes, ks_seg: bytes, tail_only: bool = False) -> tuple[bytes, bool, int]:
    """
    Decrypt the tail of a victim blob using the tail of ks_seg.

    Steps:
      1) If len(victim_blob) >= |KS|+16, strip 16-byte tag.
      2) XOR the last min(|KS|, |CT_region|) bytes with the last min(|KS|, |CT_region|) bytes of KS.

    Returns:
      (recovered_bytes, tag_stripped, recovered_tail_len)

    When tail_only=False (default): returns a CT-length buffer with the recovered tail filled
    and the head as zeros. If tail_only=True: returns only the recovered tail bytes.
    """
    ct_region, tag_stripped = _maybe_strip_tag_for_victim(victim_blob, len(ks_seg))
    usable = min(len(ks_seg), len(ct_region))
    if usable == 0:
        return (b"" if tail_only else bytes(len(ct_region))), tag_stripped, 0

    ct_tail = ct_region[-usable:]
    ks_tail = ks_seg[-usable:]
    pt_tail = bytes(c ^ k for c, k in zip(ct_tail, ks_tail))

    if tail_only:
        return pt_tail, tag_stripped, usable

    out = bytearray(len(ct_region))
    out[-usable:] = pt_tail
    return bytes(out), tag_stripped, usable

# ---------- UI ----------

def interactive():
    print("Hackstreamcipher (suffix-only, no AAD)")
    print("Derive keystream from a known PT + blob, then decrypt victim blobs by tail alignment.\n")

    pt_path   = input("Path to known plaintext file: ").strip()
    blob_path = input("Path to known ciphertext blob (CT[||TAG], AAD may precede; ignored): ").strip()

    try:
        pt   = readb(pt_path)
        blob = readb(blob_path)
    except Exception as e:
        print("Error reading files:", e)
        return

    try:
        ks, offset, stripped = recover_keystream_suffix(pt, blob)
    except Exception as e:
        print("Error computing keystream:", e)
        return

    print(f"[OK] KS len={len(ks)}  suffix-offset={offset}  tag_stripped={stripped}")
    print("KS preview (first 64 bytes hex):", ks[:64].hex())

    if input("Save keystream to file? (y/N): ").strip().lower() == 'y':
        outks = input("Keystream output path (default merged.ks): ").strip() or "merged.ks"
        writeb(outks, ks)
        print("Saved", outks)

    tail_only = input("Emit only recovered tail (not CT-length buffer)? (y/N): ").strip().lower() == 'y'

    while True:
        v = input("Victim blob to decrypt (empty to exit): ").strip()
        if not v:
            break
        try:
            vb = readb(v)
        except Exception as e:
            print("Error reading victim:", e)
            continue

        rec, v_stripped, usable = decrypt_victim_suffix(vb, ks, tail_only=tail_only)
        outp = Path(v).with_suffix(".tail.bin" if tail_only else ".pt.bin")
        writeb(outp, rec)
        print(f"Saved {outp}  (victim_tag_stripped={v_stripped}, recovered_tail_bytes={usable})")

def main():
    ap = argparse.ArgumentParser(description="Keystream extractor (suffix-only, no AAD)")
    ap.add_argument("--pt", help="known plaintext file")
    ap.add_argument("--blob", help="known ciphertext blob (CT[||TAG], AAD may precede; ignored)")
    ap.add_argument("--out-keystream", help="write recovered keystream segment to file")
    ap.add_argument("--decrypt", nargs="*", help="victim blobs to decrypt (suffix-only; CT[||TAG])")
    ap.add_argument("--tail-only", action="store_true", help="emit only recovered tail bytes for victims")
    args = ap.parse_args()

    # Interactive if key inputs are missing
    if not args.pt or not args.blob:
        return interactive()

    try:
        pt   = readb(args.pt)
        blob = readb(args.blob)
        ks, offset, stripped = recover_keystream_suffix(pt, blob)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)

    print(f"[OK] KS len={len(ks)}  suffix-offset={offset}  tag_stripped={stripped}")
    if args.out_keystream:
        writeb(args.out_keystream, ks)
        print("Wrote keystream to", args.out_keystream)

    if args.decrypt:
        for v in args.decrypt:
            try:
                vb = readb(v)
            except Exception as e:
                print("Error reading victim:", v, e)
                continue
            rec, v_stripped, usable = decrypt_victim_suffix(vb, ks, tail_only=args.tail_only)
            outp = Path(v).with_suffix(".tail.bin" if args.tail_only else ".pt.bin")
            writeb(outp, rec)
            print(f"Decrypted {v} -> {outp}  (victim_tag_stripped={v_stripped}, recovered_tail_bytes={usable})")

if __name__ == "__main__":
    main()
