#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# RC4 — Teaching Version (KSA + PRGA) with step-by-step prints
# -----------------------------------------------------------------------------
# Verbosity:
#   0 = quiet (just outputs ciphertext/plaintext/keystream)
#   1 = high-level: KSA summary, PRGA summary, drop count, lengths
#   2 = per-step KSA and first N PRGA bytes (configurable), XOR steps
#   3 = like 2 + more internal detail (j updates, S dumps at checkpoints)
#
# Handy flags:
#   --pause                : pause after phases (press Enter)
#   --no-overview          : skip the algorithm overview banner
#   --ksa-steps N          : print first N KSA steps in detail (default 16)
#   --prga-bytes N         : print first N PRGA bytes in detail (default 16)
#   --dump-s-every N       : full S dump every N KSA steps (default 64; 0=never)
#   --drop-n N             : drop first N keystream bytes before use (default 0)
#   --hex                  : interpret key/pt/ct/keystream-length as hex where applicable
#
# SECURITY NOTE: RC4 is obsolete for real-world security (many biases/attacks).
# This code is for teaching/demonstration ONLY and is NOT constant-time.

import argparse
from typing import Iterator, List, Tuple

# ==============================
# Overview banner
# ==============================

def print_overview():
    print(r"""
================================================================================
RC4 — Algorithm Overview (TEACHING MODE)
================================================================================

Key Scheduling Algorithm (KSA):
  Input: key bytes K[0..keylen-1]
  S := [0,1,2,...,255]
  j := 0
  For i from 0 to 255:
     j = (j + S[i] + K[i mod keylen]) mod 256
     swap S[i], S[j]

Pseudo-Random Generation Algorithm (PRGA):
  i := 0; j := 0
  Repeat for each output byte:
     i = (i + 1) mod 256
     j = (j + S[i]) mod 256
     swap S[i], S[j]
     keystream byte = S[(S[i] + S[j]) mod 256]

Encryption/Decryption (stream XOR):
  ciphertext = plaintext XOR keystream
  (same operation to decrypt)

Teaching options:
  • You can optionally "drop" the first N bytes of the keystream (RC4-dropN)
    to avoid early biases in demonstrations.
  • Verbosity controls show KSA/PRGA internals, swaps, and the S permutation.

This code is for lecture/demo only.
================================================================================
""")

# ==============================
# Utilities
# ==============================

def maybe_pause(do_pause: bool, msg="(press Enter)"):
    if do_pause:
        try:
            input(msg)
        except EOFError:
            pass

def hexb(b: bytes) -> str:
    return b.hex()

def chunk(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i+size]

def dump_S(S: List[int], label: str = "", columns: int = 16):
    if label:
        print(f"[S dump] {label}")
    for row in chunk(S, columns):
        print("  " + " ".join(f"{x:02x}" for x in row))

# ==============================
# RC4 core (with verbose options)
# ==============================

def rc4_ksa_verbose(key: bytes,
                    verbose: int = 0,
                    pause: bool = False,
                    ksa_steps: int = 16,
                    dump_s_every: int = 64) -> List[int]:
    keylen = len(key)
    if keylen == 0:
        raise ValueError("key must be non-empty")
    S = list(range(256))
    j = 0
    if verbose >= 1:
        print(f"[KSA] key length = {keylen}")
        print("[KSA] Initialize S = [0..255]")
        if verbose >= 3:
            dump_S(S, "initial S")
    for i in range(256):
        # key byte used at this step:
        kbyte = key[i % keylen]
        j = (j + S[i] + kbyte) & 0xFF
        if verbose >= 2 and i < ksa_steps:
            print(f"[KSA] i={i:3d}  j = (j + S[i] + key[i%len]) mod 256 "
                  f"= ({(j - S[i] - kbyte) & 0xFF:3d} + {S[i]:3d} + {kbyte:3d}) mod 256 -> {j:3d}")
            print(f"      swap S[{i}]={S[i]:3d} and S[{j}]={S[j]:3d}")
        S[i], S[j] = S[j], S[i]
        if verbose >= 3:
            # occasional S dump
            do_dump = (dump_s_every > 0 and (i % dump_s_every == 0)) or (i in (0,1,2,3,4,5,31,63,127,255))
            if do_dump:
                dump_S(S, f"after i={i}")
    if verbose >= 1:
        print("[KSA] Completed.")
    maybe_pause(pause, "End of KSA. Press Enter to continue...")
    return S

def rc4_prga_stream(S: List[int]) -> Iterator[int]:
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        yield K

def rc4_prga_verbose(S: List[int],
                     nbytes: int,
                     verbose: int = 0,
                     pause: bool = False,
                     prga_detail: int = 16) -> bytes:
    """
    Generate nbytes of keystream, printing first prga_detail steps if verbose>=2.
    """
    i = 0
    j = 0
    out = bytearray()
    if verbose >= 1:
        print(f"[PRGA] Generating {nbytes} byte(s) of keystream")
    for t in range(nbytes):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        if verbose >= 2 and t < prga_detail:
            print(f"[PRGA] t={t:3d}  i=(i+1)&255 -> {i:3d} ; j=(j+S[i])&255 -> {j:3d} (S[i]={S[i]:3d})")
            print(f"       swap S[{i}]={S[i]:3d} <-> S[{j}]={S[j]:3d}")
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(K)
        if verbose >= 2 and t < prga_detail:
            print(f"       keystream byte = S[(S[i]+S[j])&255] = {K:3d} (0x{K:02x})")
    if verbose >= 1:
        print("[PRGA] Done.")
    maybe_pause(pause, "End of PRGA. Press Enter to continue...")
    return bytes(out)

def rc4_stream_verbose(key: bytes,
                       data: bytes,
                       *,
                       drop_n: int = 0,
                       verbose: int = 0,
                       pause: bool = False,
                       ksa_steps: int = 16,
                       prga_detail: int = 16,
                       dump_s_every: int = 64) -> Tuple[bytes, bytes]:
    """
    Returns (cipher_or_plaintext, first_used_keystream). The same function
    encrypts or decrypts (stream XOR symmetry).
    """
    if verbose >= 1:
        print(f"[INFO] data length = {len(data)} byte(s); drop_n = {drop_n}")
    S = rc4_ksa_verbose(key, verbose=verbose, pause=pause,
                        ksa_steps=ksa_steps, dump_s_every=dump_s_every)

    # Discard first drop_n bytes (RC4-dropN)
    if drop_n > 0:
        if verbose >= 1:
            print(f"[DROP] Discarding first {drop_n} keystream byte(s) (RC4-drop{drop_n})")
        _ = rc4_prga_verbose(S, drop_n, verbose=2 if verbose >= 1 else 0,
                             pause=False, prga_detail=min(prga_detail, drop_n))
    # Produce keystream for data
    ks = rc4_prga_verbose(S, len(data), verbose=verbose, pause=pause, prga_detail=prga_detail)

    out = bytearray(len(data))
    first_print = min(len(data), prga_detail) if verbose >= 2 else 0
    for idx, (ptb, ksb) in enumerate(zip(data, ks)):
        out[idx] = ptb ^ ksb
        if idx < first_print and verbose >= 2:
            print(f"[XOR] off={idx:4d}  in=0x{ptb:02x}  ks=0x{ksb:02x}  out=0x{out[idx]:02x}")
    if verbose >= 1:
        print("[XOR] Completed stream XOR.")
    return bytes(out), ks

# ==============================
# CLI helpers
# ==============================

def parse_hex_or_utf8(s: str, is_hex: bool) -> bytes:
    if is_hex:
        s = s.strip().replace(" ", "").replace("\n", "")
        # allow odd-length hex as friendly error
        if len(s) % 2 != 0:
            raise ValueError("hex string must have even length")
        return bytes.fromhex(s)
    return s.encode("utf-8")

# ==============================
# Self-test (simple)
# ==============================

def selftest(verbose: int = 2, pause: bool = False, drop_n: int = 0,
             ksa_steps: int = 8, prga_detail: int = 8, dump_s_every: int = 128):
    """
    Minimal identity check: encrypt then decrypt and compare.
    (We avoid asserting fixed ciphertext to keep the test simple in class.)
    """
    key = b"Key"                    # classic small key for demo
    pt  = b"Plaintext"
    if verbose >= 1:
        print("[Selftest] key=b'Key', pt=b'Plaintext'")
    ct, ks1 = rc4_stream_verbose(key, pt, drop_n=drop_n, verbose=verbose,
                                 pause=pause, ksa_steps=ksa_steps,
                                 prga_detail=prga_detail, dump_s_every=dump_s_every)
    if verbose >= 1:
        print(f"[Selftest] ciphertext = {hexb(ct)}")
    rt, ks2 = rc4_stream_verbose(key, ct, drop_n=drop_n, verbose=0)  # quiet on second pass
    ok = (rt == pt)
    print("recover ok:", ok)
    if not ok:
        print(f"recovered = {rt!r}")

# ==============================
# CLI
# ==============================

def main():
    ap = argparse.ArgumentParser(description="RC4 (Teaching Mode) — KSA and PRGA with step-by-step prints")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--key", required=True, help="Key (hex or utf8)")
        p.add_argument("--hex", action="store_true", help="Interpret key/pt/ct as hex")
        p.add_argument("--verbose", type=int, default=0, help="0..3 (3 = most detail)")
        p.add_argument("--pause", action="store_true", help="Pause after phases (press Enter)")
        p.add_argument("--no-overview", action="store_true", help="Skip algorithm overview banner")
        p.add_argument("--ksa-steps", type=int, default=16, help="Detailed KSA steps to print (default 16)")
        p.add_argument("--prga-bytes", type=int, default=16, help="Detailed PRGA bytes to print (default 16)")
        p.add_argument("--dump-s-every", type=int, default=64, help="Dump S every N KSA steps (0=never; default 64)")
        p.add_argument("--drop-n", type=int, default=0, help="Drop N keystream bytes before use (RC4-dropN)")

    # encrypt
    pe = sub.add_parser("encrypt", help="Encrypt (stream XOR)")
    add_common(pe)
    pe.add_argument("--pt", required=True, help="Plaintext (hex or utf8)")

    # decrypt
    pd = sub.add_parser("decrypt", help="Decrypt (stream XOR)")
    add_common(pd)
    pd.add_argument("--ct", required=True, help="Ciphertext (hex or utf8)")

    # keystream
    pk = sub.add_parser("keystream", help="Generate keystream bytes for a given key")
    pk.add_argument("--key", required=True, help="Key (hex or utf8)")
    pk.add_argument("--n", required=True, help="Number of bytes (decimal by default, hex if --hex)")
    pk.add_argument("--hex", action="store_true", help="Interpret key and n as hex")
    pk.add_argument("--verbose", type=int, default=0, help="0..3")
    pk.add_argument("--pause", action="store_true")
    pk.add_argument("--no-overview", action="store_true")
    pk.add_argument("--ksa-steps", type=int, default=16)
    pk.add_argument("--prga-bytes", type=int, default=16)
    pk.add_argument("--dump-s-every", type=int, default=64)
    pk.add_argument("--drop-n", type=int, default=0)

    # selftest
    ps = sub.add_parser("selftest", help="Encrypt-then-decrypt identity check")
    ps.add_argument("--verbose", type=int, default=2)
    ps.add_argument("--pause", action="store_true")
    ps.add_argument("--drop-n", type=int, default=0)
    ps.add_argument("--ksa-steps", type=int, default=8)
    ps.add_argument("--prga-bytes", type=int, default=8)
    ps.add_argument("--dump-s-every", type=int, default=128)
    ps.add_argument("--no-overview", action="store_true")

    args = ap.parse_args()

    if args.cmd == "encrypt":
        if not getattr(args, "no_overview", False):
            print_overview()
        key = parse_hex_or_utf8(args.key, args.hex)
        pt  = parse_hex_or_utf8(args.pt,  args.hex)
        ct, ks = rc4_stream_verbose(
            key, pt,
            drop_n=args.drop_n,
            verbose=args.verbose,
            pause=args.pause,
            ksa_steps=args.ksa_steps,
            prga_detail=args.prga_bytes,
            dump_s_every=args.dump_s_every
        )
        print("ciphertext:", hexb(ct))

    elif args.cmd == "decrypt":
        if not getattr(args, "no_overview", False):
            print_overview()
        key = parse_hex_or_utf8(args.key, args.hex)
        ct  = parse_hex_or_utf8(args.ct,  args.hex)
        pt, ks = rc4_stream_verbose(
            key, ct,
            drop_n=args.drop_n,
            verbose=args.verbose,
            pause=args.pause,
            ksa_steps=args.ksa_steps,
            prga_detail=args.prga_bytes,
            dump_s_every=args.dump_s_every
        )
        print("plaintext :", hexb(pt))

    elif args.cmd == "keystream":
        if not getattr(args, "no_overview", False):
            print_overview()
        key = parse_hex_or_utf8(args.key, args.hex)
        if args.hex:
            n = int(args.n, 16)
        else:
            n = int(args.n, 10)
        if n < 0:
            raise ValueError("n must be non-negative")
        # Build S, drop, then produce n bytes of keystream (no XOR)
        S = rc4_ksa_verbose(key, verbose=args.verbose, pause=args.pause,
                            ksa_steps=args.ksa_steps, dump_s_every=args.dump_s_every)
        if args.drop_n > 0:
            if args.verbose >= 1:
                print(f"[DROP] Discarding first {args.drop_n} keystream byte(s)")
            _ = rc4_prga_verbose(S, args.drop_n, verbose=2 if args.verbose >= 1 else 0,
                                 pause=False, prga_detail=min(args.prga_bytes, args.drop_n))
        ks = rc4_prga_verbose(S, n, verbose=args.verbose, pause=args.pause, prga_detail=args.prga_bytes)
        print("keystream :", hexb(ks))

    elif args.cmd == "selftest":
        if not getattr(args, "no_overview", False):
            print_overview()
        selftest(verbose=args.verbose, pause=args.pause, drop_n=args.drop_n,
                 ksa_steps=args.ksa_steps, prga_detail=args.prga_bytes, dump_s_every=args.dump_s_every)

if __name__ == "__main__":
    main()
