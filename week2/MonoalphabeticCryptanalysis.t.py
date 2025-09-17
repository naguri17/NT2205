#!/usr/bin/env python3
"""Cryptanalysis helpers for monoalphabetic ciphers (9 algorithms).

Usage examples:
  python3 monocrypt.py caesar --ciphertext "KHOOR ZRUOG"
  python3 monocrypt.py affine --ciphertext "..." 
  python3 monocrypt.py substitution --ciphertext "..."

This script implements simple attacks:
 - Caesar/ROT-N: brute force all shifts and score by English word matches
 - Atbash: single mapping
 - Affine: brute force (a,b) with gcd(a,26)=1
 - ROT-N: brute force n
 - A1Z26: parse numbers -> letters
 - Substitution/Keyword/Pigpen: hillclimbing local search using fitness combining letter-freq chi-square and common-word matches
 - Homophonic: simple frequency mapping (symbols -> letters) using frequency ranking

Note: these are heuristic attackers suitable for classroom-sized examples.
"""

import argparse
import math
import random
import string
from collections import Counter

ALPHABET = string.ascii_uppercase
ENGLISH_FREQ = {
    'E': 12.0,'T':9.1,'A':8.2,'O':7.5,'I':7.0,'N':6.7,'S':6.3,'R':6.0,
    'H':6.1,'L':4.0,'D':4.3,'C':2.8,'U':2.8,'M':2.4,'F':2.2,'Y':2.0,'W':2.4,
    'G':2.0,'P':1.9,'B':1.5,'V':1.0,'K':0.8,'X':0.15,'Q':0.1,'J':0.15,'Z':0.07
}
COMMON_WORDS = ["THE","AND","TO","OF","IN","IS","I","THAT","IT","FOR","YOU","NOT","WITH"]

# ----------------- scoring -----------------

def score_text_wordmatch(text: str) -> float:
    """Score by counting occurrences of common English words (heuristic)."""
    t = text.upper()
    score = 0.0
    for w in COMMON_WORDS:
        score += t.count(w) * (len(w))
    return score


def score_text_chi_square(text: str) -> float:
    """Chi-square distance between text letter freq and English freq (lower is better)."""
    text = ''.join(ch for ch in text.upper() if ch in ALPHABET)
    n = len(text)
    if n == 0:
        return float('inf')
    counts = Counter(text)
    chi = 0.0
    for ch in ALPHABET:
        observed = counts.get(ch,0)
        expected = ENGLISH_FREQ.get(ch,0)/100.0 * n
        # avoid zero expected
        if expected > 0:
            chi += (observed - expected)**2 / expected
    return chi


def fitness(text: str) -> float:
    """Combined fitness: higher is better. We'll invert chi-square and add word matches."""
    # higher wordmatch is good, lower chi is good
    chi = score_text_chi_square(text)
    words = score_text_wordmatch(text)
    # convert chi to positive by negative sign: lower chi => larger contribution
    return words - 0.2 * chi

# ----------------- Caesar / ROT / Atbash / Affine / A1Z26 -----------------

def caesar_bruteforce(cipher: str):
    results = []
    for s in range(26):
        plain = ''.join(ALPHABET[(ALPHABET.index(ch) - s) % 26] if ch in ALPHABET else ch for ch in cipher.upper())
        results.append((s, plain, fitness(plain)))
    results.sort(key=lambda x: x[2], reverse=True)
    return results


def atbash(cipher: str):
    table = {ch: ALPHABET[25-i] for i,ch in enumerate(ALPHABET)}
    plain = ''.join(table[ch] if ch in table else ch for ch in cipher.upper())
    return plain


def affine_bruteforce(cipher: str):
    results = []
    coprimes = [a for a in range(1,26) if math.gcd(a,26)==1]
    for a in coprimes:
        a_inv = pow(a, -1, 26)
        for b in range(26):
            plain = ''.join(ALPHABET[(a_inv*(ALPHABET.index(ch)-b))%26] if ch in ALPHABET else ch for ch in cipher.upper())
            results.append(((a,b), plain, fitness(plain)))
    results.sort(key=lambda x: x[2], reverse=True)
    return results


def rotN_bruteforce(cipher: str):
    return caesar_bruteforce(cipher)


def a1z26_attack(cipher: str):
    # Try to map numbers to letters assuming space separated numbers
    tokens = cipher.strip().split()
    if all(token.isdigit() for token in tokens):
        try:
            letters = [ALPHABET[int(t)-1] for t in tokens]
            return ''.join(letters)
        except Exception:
            return None
    # fallback: try to extract numbers from string
    nums = []
    cur = ''
    for ch in cipher:
        if ch.isdigit():
            cur += ch
        else:
            if cur:
                nums.append(cur)
                cur=''
    if cur:
        nums.append(cur)
    if nums:
        try:
            return ''.join(ALPHABET[int(n)-1] for n in nums)
        except Exception:
            return None
    return None

# ----------------- Homophonic frequency attack (simple) -----------------

def homophonic_simple_freq(cipher: str):
    # Count symbol frequencies and map by rank to English frequency ranking
    # For homophonic ciphertext symbols may be non-letter characters
    counts = Counter([ch for ch in cipher if ch != ' ' and ch != '\n'])
    symbols_sorted = [sym for sym,_ in counts.most_common()]
    # english ranking
    eng_ranking = [k for k,_ in sorted(ENGLISH_FREQ.items(), key=lambda x:-x[1])]
    mapping = {}
    for i,sym in enumerate(symbols_sorted):
        if i < len(eng_ranking):
            mapping[sym] = eng_ranking[i]
        else:
            mapping[sym] = 'X'
    # produce tentative plaintext
    plain = ''.join(mapping.get(ch, ch) for ch in cipher)
    return plain, mapping

# ----------------- Substitution / Keyword / Pigpen: hillclimb -----------------

def random_substitution_key():
    letters = list(ALPHABET)
    random.shuffle(letters)
    return ''.join(letters)


def decode_sub_with_key(cipher: str, key_str: str) -> str:
    key_str = key_str.upper()
    mapping = {ALPHABET[i]: key_str[i] for i in range(26)}
    inv = {v:k for k,v in mapping.items()}
    return ''.join(inv.get(ch, ch) for ch in cipher.upper())


def score_for_key(cipher: str, key_str: str) -> float:
    plain = decode_sub_with_key(cipher, key_str)
    return fitness(plain)


def neighbor_swap_key(key: str):
    lst = list(key)
    i,j = random.sample(range(26),2)
    lst[i], lst[j] = lst[j], lst[i]
    return ''.join(lst)


def hillclimb_substitution(cipher: str, restarts=20, iters=2000):
    best_overall = (None, -1e9)
    for r in range(restarts):
        key = random_substitution_key()
        best_local = (key, score_for_key(cipher,key))
        improved = True
        no_improve = 0
        for it in range(iters):
            cand = neighbor_swap_key(best_local[0])
            s = score_for_key(cipher, cand)
            if s > best_local[1]:
                best_local = (cand, s)
                no_improve = 0
            else:
                no_improve += 1
            if no_improve > 500:
                break
        if best_local[1] > best_overall[1]:
            best_overall = best_local
    final_plain = decode_sub_with_key(cipher, best_overall[0]) if best_overall[0] else ''
    return best_overall[0], final_plain, best_overall[1]

# ----------------- CLI wiring -----------------

def main():
    parser = argparse.ArgumentParser(description="Monoalphabetic Cryptanalysis Helpers")
    parser.add_argument('cipher', choices=['caesar','atbash','affine','rot','a1z26','substitution','keyword','homophonic','pigpen'], help='cipher type to attack')
    parser.add_argument('--ciphertext', '-c', required=True, help='Ciphertext to analyze')
    parser.add_argument('--top', type=int, default=5, help='Top results to show for brute-force attacks')
    parser.add_argument('--restarts', type=int, default=20, help='Restarts for substitution hillclimb')
    parser.add_argument('--iters', type=int, default=2000, help='Iterations per restart for substitution hillclimb')
    args = parser.parse_args()

    C = args.ciphertext

    if args.cipher == 'caesar':
        res = caesar_bruteforce(C)
        for s, plain, sc in res[:args.top]:
            print(f'Shift={s}: {plain}  [score={sc:.2f}]')

    elif args.cipher == 'atbash':
        print(atbash(C))

    elif args.cipher == 'rot':
        res = rotN_bruteforce(C)
        for s, plain, sc in res[:args.top]:
            print(f'ROT={s}: {plain}  [score={sc:.2f}]')

    elif args.cipher == 'affine':
        res = affine_bruteforce(C)
        for (a,b), plain, sc in res[:args.top]:
            print(f'a={a},b={b}: {plain}  [score={sc:.2f}]')

    elif args.cipher == 'a1z26':
        print(a1z26_attack(C))

    elif args.cipher in ('substitution','keyword','pigpen'):
        key, plain, sc = hillclimb_substitution(C, restarts=args.restarts, iters=args.iters)
        print('BEST KEY:', key)
        print('PLAINTEXT:', plain)
        print('SCORE:', sc)

    elif args.cipher == 'homophonic':
        plain, mapping = homophonic_simple_freq(C)
        print('TENTATIVE PLAINTEXT:', plain)
        print('MAPPING SAMPLE (first 20):', dict(list(mapping.items())[:20]))

if __name__ == '__main__':
    main()
