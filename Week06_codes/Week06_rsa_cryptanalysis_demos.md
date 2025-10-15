# RSA Cryptanalysis Demos — Master Class Handbook

This handbook gathers **six RSA attack demonstrations** aligned with the *RSA Security Landscape* slide. Each section includes executable Python code, expected results, and discussion notes.

---

## 0. Utilities (Shared by All Demos)

```python
# Basic math helpers for RSA demos
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def invmod(a, n):
    g, x, _ = egcd(a, n)
    if g != 1: raise ValueError("no inverse")
    return x % n

def crt(remainders, moduli):
    from functools import reduce
    N = reduce(lambda a,b: a*b, moduli, 1)
    s = 0
    for r, m in zip(remainders, moduli):
        Mi = N // m
        s += r * invmod(Mi, m) * Mi
    return s % N, N

def iroot(k, n):
    lo, hi = 0, 1
    while hi**k <= n: hi <<= 1
    while lo < hi:
        mid = (lo + hi + 1) >> 1
        if mid**k <= n: lo = mid
        else: hi = mid - 1
    return lo, (lo**k == n)

def is_probably_prime(n):
    import random
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0: return n == p
    d, s = n-1, 0
    while d % 2 == 0: d//=2; s+=1
    bases = small_primes
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1: break
        else:
            return False
    return True

def gen_prime(bits, seed=12345):
    import random
    rnd = random.Random(seed)
    while True:
        p = (rnd.getrandbits(bits) | (1 << (bits-1)) | 1)
        if is_probably_prime(p): return p

def rsa_keygen(p, q, e):
    n = p*q
    phi = (p-1)*(q-1)
    d = invmod(e, phi)
    return n, e, d, p, q
```

---

## 1. Shared Prime Attack (Keygen/Operations Flaw)

```python
from math import gcd
p = gen_prime(256, 1)
q1 = gen_prime(256, 2)
q2 = gen_prime(256, 3)
e = 65537
n1, e1, d1, p1, q1 = rsa_keygen(p, q1, e)
n2, e2, d2, p2, q2 = rsa_keygen(p, q2, e)
g = gcd(n1, n2)
phi1 = (g-1)*((n1//g)-1)
d1_recovered = invmod(e1, phi1)
print("Recovered d1==real?", d1_recovered == d1)
```

**Lesson:** shared primes instantly expose all private keys.

---

## 2. Common Modulus Attack

```python
p = gen_prime(256, 11)
q = gen_prime(256, 22)
n = p*q
e1, e2 = 17, 65537
m = 12345678901234567890
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
g, a, b = egcd(e1, e2)

def modexp_signed(base, exp, mod):
    return pow(base, exp, mod) if exp >= 0 else pow(invmod(base, mod), -exp, mod)

m_recovered = (modexp_signed(c1, a, n) * modexp_signed(c2, b, n)) % n
print("Recovered m:", m_recovered, m_recovered == m)
```

**Lesson:** never reuse modulus `n` with different exponents.

---

## 3. Håstad’s Broadcast Attack (e=3, No Padding)

```python
e = 3
ps = [gen_prime(256, s) for s in (101,102,103)]
qs = [gen_prime(256, s) for s in (201,202,203)]
ns = [p*q for p,q in zip(ps,qs)]
m = 2**120 + 1337
cs = [pow(m, e, n) for n in ns]
x, N = crt(cs, ns)
root, exact = iroot(e, x)
print("Exact cube root?", exact, "Recovered m correct?", root == m)
```

**Lesson:** OAEP padding prevents this attack.

---

## 4. Wiener’s Attack (Small d)

```python
def cont_frac(n, d):
    while d:
        a = n // d
        yield a
        n, d = d, n - a*d

def convergents(frac):
    num1, num2 = 1, 0
    den1, den2 = 0, 1
    for a in frac:
        num = a*num1 + num2
        den = a*den1 + den2
        yield num, den
        num2, num1 = num1, num
        den2, den1 = den1, den

def wiener(e, n):
    for k, d in convergents(list(cont_frac(e, n))):
        if k == 0: continue
        if (e*d - 1) % k != 0: continue
        phi = (e*d - 1) // k
        b = n - phi + 1
        disc = b*b - 4*n
        if disc >= 0:
            r = int(disc**0.5)
            if r*r == disc:
                p = (b + r)//2
                q = (b - r)//2
                if p*q == n and p>1 and q>1:
                    return d, p, q
    return None

p = gen_prime(256, 777)
q = gen_prime(256, 778)
n  = p*q
phi = (p-1)*(q-1)
d_small = 2**16 + 3
e = invmod(d_small, phi)
res = wiener(e, n)
print("Recovered (d,p,q)?", res is not None)
```

**Lesson:** enforce large private exponents.

---

## 5. Bellcore Fault Attack (CRT Recombination)

```python
def crt_rsa_sign(m, p, q, d):
    dp, dq = d % (p-1), d % (q-1)
    qinv = invmod(q, p)
    sp = pow(m, dp, p)
    sq = pow(m, dq, q)
    h = (qinv * (sp - sq)) % p
    return (sq + h*q) % (p*q)

p = gen_prime(256, 9001)
q = gen_prime(256, 9002)
n, e, d, p, q = rsa_keygen(p, q, 65537)
m = 98765432123456789
s_good = crt_rsa_sign(m, p, q, d)
s_fault = (s_good + 12345) % n
leaked = __import__('math').gcd(n, (s_good - s_fault) % n)
print("Leaked factor prime?", is_probably_prime(leaked))
```

**Lesson:** verify results before releasing signatures.

---

## 6. Timing Side-Channel (Variable Exponentiation)

```python
def sqr_mul_leaky(base, exp, mod):
    ops = 0
    x = 1
    b = base % mod
    for bit in bin(exp)[2:]:
        x = (x*x) % mod; ops += 1
        if bit == '1':
            x = (x*b) % mod; ops += 1
    return x, ops

def sqr_mul_constant(base, exp, mod):
    R0, R1 = 1, base % mod
    for bit in bin(exp)[2:]:
        if bit == '0':
            R1 = (R0 * R1) % mod
            R0 = (R0 * R0) % mod
        else:
            R0 = (R0 * R1) % mod
            R1 = (R1 * R1) % mod
    return R0

p = gen_prime(256, 3141)
q = gen_prime(256, 2718)
n, e, d, p, q = rsa_keygen(p, q, 65537)
for base in [2,3,5,7,11]:
    _, ops = sqr_mul_leaky(base, d, n)
    print(f"base={base}: ops={ops}")
```

**Lesson:** use constant-time exponentiation with blinding.

---

## Hardening Summary

- **Use OAEP/PSS** padding.
- **Strong randomness** → unique primes.
- **Avoid small d, e**, enforce security bounds.
- **Constant-time and blinding** for private ops.
- **CRT verification** before output.
- **Batch GCD checks** across keys.
- **Transition plan:** PQC KEM + RSA/PSS hybrid.

---
