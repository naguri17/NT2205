# NT2205 Windows PowerShell Handbook — Patterned Steps (OpenSSL CLI)

> **Style:** Every section follows the same pattern — *Generate → Inspect/Verify → Run → Verify (hex/hash)* — so students can copy, run, and note outcomes. Target **PowerShell** with **OpenSSL ≥ 3.0** on PATH.

---

## 0) Setup (once)

Download and setup ps 7
<https://github.com/PowerShell/PowerShell/releases/download/v7.5.3/PowerShell-7.5.3-win-x64.exe>

Run PowerShell 7
$PSVersionTable.PSVersion
$PSStyle.OutputRendering = 'PlainText'

```powershell
# Check OpenSSL
openssl version -a

# Workspace
$lab = Join-Path $env:USERPROFILE 'nt2205-lab'
New-Item -ItemType Directory -Force $lab | Out-Null
Set-Location $lab

# Hex helpers
Set-Alias hex Format-Hex
function Get-Hex($Path){ -join ((Get-Content -AsByteStream $Path) | ForEach-Object { $_.ToString('x2') }) }
```

---

## 1) RSA

### 1.1 RSA keygen (with CRT)

```powershell
# Gen Private key (enter passphrase twice if prompted)
openssl genpkey -algorithm RSA `
  -pkeyopt rsa_keygen_bits:3072 `
  -pkeyopt rsa_keygen_pubexp:17 `
  -out rsa_priv.pem

# e = 17

# Gen public key
openssl pkey -in rsa_priv.pem -pubout -out rsa_pub.pem

# Verify the keys (CRT params dp,dq,iqmp)
# Private
openssl pkey -in rsa_priv.pem -text -noout

# Public
openssl pkey -in rsa_pub.pem -pubin -text -noout

# Optional: use a larger e, e.g., 2^32+1
openssl genpkey -algorithm RSA `
  -pkeyopt rsa_keygen_bits:3072 `
  -pkeyopt rsa_keygen_pubexp:4294967297 `
  -out rsa_priv.pem

openssl pkey -in rsa_priv.pem -pubout -out rsa_pub.pem
```

### 1.2 RSA‑OAEP (Encrypt/Decrypt)

```powershell
# Input plaintext
Set-Content -NoNewline -Path msg.txt -Value 'hello UIT NT219 with OAEP padding'

# Verify files
Get-ChildItem

# Encrypt (OAEP: SHA-256 / MGF1-SHA-256)
openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -in msg.txt -out msg.oaep `
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256

# Inspect bytes
hex .\msg.txt
hex .\msg.oaep

# Decrypt
openssl pkeyutl -decrypt -inkey rsa_priv.pem -in msg.oaep -out msg.dec `
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256

# Verify
hex .\msg.dec
if ((Get-FileHash msg.txt).Hash -eq (Get-FileHash msg.dec).Hash) { 'OK: files identical' } else { 'DIFF' }
```

### 1.3 RSA‑KEM (RAW demo — insecure by design)

```powershell
# (A) Tạo bí mật ngắn (demo) — 16 bytes
[Environment]::CurrentDirectory = (Get-Location).Path
openssl rand -out .\r.bin 16
Format-Hex .\r.bin

# (B) Lấy độ dài mô-đun kN (bytes) từ public key
$modLine = & openssl rsa -pubin -in .\rsa_pub.pem -modulus -noout
if (-not $modLine) { throw "Không đọc được modulus từ rsa_pub.pem" }
$modHex = $modLine -replace '^Modulus=',''
[int]$kN = [math]::Ceiling($modHex.Length / 2.0)
"$kN bytes"

# Tạo mảng x độ dài kN bytes và chép r vào đuôi (left-pad bằng 0x00)
$r = [IO.File]::ReadAllBytes('.\r.bin')
$x = New-Object byte[] $kN
[Array]::Copy($r, 0, $x, $kN - $r.Length, $r.Length)
[IO.File]::WriteAllBytes('.\x.bin', $x)
Format-Hex .\x.bin

# (D) RAW RSA (NO PADDING) — INSECURE DEMO
# Encryption key
openssl pkeyutl -encrypt -pubin -inkey .\rsa_pub.pem `
  -in .\x.bin -out .\kem_raw.c -pkeyopt rsa_padding_mode:none

# Verify cipher
hex .\kem_raw.c

# Decrypt
openssl pkeyutl -decrypt -inkey .\rsa_priv.pem `
  -in .\kem_raw.c -out .\x.dec -pkeyopt rsa_padding_mode:none

# Verify 
hex .\x.dec

# (E) Remove  padding 0x00
$len = (Get-Item .\r.bin).Length
$d   = [IO.File]::ReadAllBytes('.\x.dec')
$tail = New-Object byte[] $len
[Array]::Copy($d, $d.Length - $len, $tail, 0, $len)
[IO.File]::WriteAllBytes('.\r_tail.bin', $tail)

# Verify
hex .\r_tail.bin

# Check hashs
if ((Get-FileHash .\r.bin).Hash -eq (Get-FileHash .\r_tail.bin).Hash) {
  'Recovered r (DEMO — INSECURE)'
} else {
  'Mismatch'
}
```

### 1.4 RAW cryptanalysis (no private key)

**When can a RAW RSA ciphertext be decrypted without the private key?**

* **Small public exponent** `e` (e.g., 3, 17) **and** **small input** `x` (here `x = I2OSP(r)` with `|r| = 16 B`).
* If `x^e < n` then `c = x^e` as an integer (no reduction) ⇒ take the **integer e‑th root** to recover `x` (and thus `r`).
* More generally, search for `k` so that **`c + k*n`** is a perfect `e`‑th power (the "c + k·n" trick).

> Demo tip: Use a key with **e = 17** to see the integer‑root break immediately. With `e = 65537`, the root test usually fails; the `c + k*n` search still illustrates the idea (use a small `maxK`).

```powershell
#  Copy all below with two enters to run the code may set -ThrottleLimit 6 to other greater than 6
# maxK=200000000000 may larger

# --- Cryptanalyse RAW RSA ciphertext (no private key) ---
[Environment]::CurrentDirectory = (Get-Location).Path

# Read (e, n) from public key
$pub = & openssl pkey -in ./rsa_pub.pem -pubin -text -noout
$e   = [int](([regex]::Match(($pub -join ' '), 'Exponent:\s+(\d+)')).Groups[1].Value); if(-not $e){$e=65537}
$modLine = & openssl rsa -pubin -in ./rsa_pub.pem -modulus -noout
$modHex  = $modLine -replace '^Modulus=',''

# N from hex -> BigInteger (little-endian, positive)
[byte[]]$nBE = for($i=0;$i -lt $modHex.Length;$i+=2){ [Convert]::ToByte($modHex.Substring($i,2),16) }
$nb = $nBE.Clone(); [Array]::Reverse($nb); $nb = $nb + ,0
$N  = [System.Numerics.BigInteger]::new($nb)

# C from r.cipher -> BigInteger 
$cBytes = [IO.File]::ReadAllBytes((Resolve-Path ./r.cipher))
$cb = $cBytes.Clone(); [Array]::Reverse($cb); $cb = $cb + ,0
$C  = [System.Numerics.BigInteger]::new($cb)

# Integer e-th root (binary search)
function IntRoot([System.Numerics.BigInteger]$X,[int]$E){
  $lo=[System.Numerics.BigInteger]::Zero; $hi=[System.Numerics.BigInteger]::One
  while([System.Numerics.BigInteger]::Pow($hi,$E) -le $X){ $hi=$hi -shl 1 }
  while($hi-$lo -gt 1){
    $mid=($lo+$hi)/2
    if([System.Numerics.BigInteger]::Pow($mid,$E) -le $X){ $lo=$mid } else { $hi=$mid }
  }
  $lo
}

# Attack 1: direct integer-root
$root = IntRoot $C $e
if([System.Numerics.BigInteger]::Pow($root,$e) -eq $C){
  'Direct integer-root SUCCESS'
  $rb=$root.ToByteArray(); [Array]::Reverse($rb); if($rb.Length -gt 1 -and $rb[0]-eq 0){ $rb=$rb[1..($rb.Length-1)] }
  $hex=($rb|ForEach-Object { $_.ToString('x2') }) -join ''; "root (big-endian hex) = 0x$hex"

  $kN=(Get-Item .\kem_raw.c -ErrorAction SilentlyContinue).Length
  if($kN){
    if($rb.Length -lt $kN){ $rbNorm=(,0*($kN-$rb.Length))+$rb } else { $rbNorm=$rb }
    $rLen=(Get-Item .\r.bin -ErrorAction SilentlyContinue).Length
    if($rLen){
      $rRec=$rbNorm[($rbNorm.Length-$rLen)..($rbNorm.Length-1)]
      [IO.File]::WriteAllBytes((Join-Path (Get-Location).Path 'r_from_root.bin'),$rRec)
      Format-Hex .\r_from_root.bin | Select-Object -First 2
    }
  }
}else{
  # Attack 2: parallel k-search (PS 7+)
  [long]$maxK=2000000000000; [long]$chunkSize=20000
  $ranges=for([long]$s=0;$s -le $maxK;$s+=$chunkSize){ $end=$s+$chunkSize-1; if($end -gt $maxK){$end=$maxK}; [pscustomobject]@{Start=$s;End=$end} }

  $result = $ranges | ForEach-Object -Parallel {
    param($range)
    function IntRoot([System.Numerics.BigInteger]$X,[int]$E){
      $lo=[System.Numerics.BigInteger]::Zero;$hi=[System.Numerics.BigInteger]::One
      while([System.Numerics.BigInteger]::Pow($hi,$E) -le $X){ $hi=$hi -shl 1 }
      while($hi-$lo -gt 1){ $mid=($lo+$hi)/2; if([System.Numerics.BigInteger]::Pow($mid,$E) -le $X){ $lo=$mid } else { $hi=$mid } }
      $lo
    }
    for([long]$k=$range.Start;$k -le $range.End;$k++){
      $T  = $using:C + ([System.Numerics.BigInteger]$k) * $using:N
      $r2 = IntRoot $T $using:e
      if([System.Numerics.BigInteger]::Pow($r2,$using:e) -eq $T){ [pscustomobject]@{ K=$k; Root=$r2 }; break }
    }
  } -ThrottleLimit 8 | Select-Object -First 1

  if($result){
    "Found k=$($result.K)"
    $rb=$result.Root.ToByteArray(); [Array]::Reverse($rb); if($rb.Length -gt 1 -and $rb[0]-eq 0){ $rb=$rb[1..($rb.Length-1)] }
    $hex=($rb|ForEach-Object { $_.ToString('x2') }) -join ''; "root (big-endian hex) = 0x$hex"

    $kN=(Get-Item .\kem_raw.c -ErrorAction SilentlyContinue).Length
    if($kN){
      if($rb.Length -lt $kN){ $rbNorm=(,0*($kN-$rb.Length))+$rb } else { $rbNorm=$rb }
      $rLen=(Get-Item .\r.bin -ErrorAction SilentlyContinue).Length
      if($rLen){
        $rRec=$rbNorm[($rbNorm.Length-$rLen)..($rbNorm.Length-1)]
        [IO.File]::WriteAllBytes((Join-Path (Get-Location).Path 'r_from_k_parallel.bin'),$rRec)
        Format-Hex .\r_from_k_parallel.bin | Select-Object -First 2
      }
    }
  }else{
    "No k in 0..$maxK"
  }
}

```

*Lesson:* RAW RSA (no padding) is deterministic, malleable, and with small `e` + small input it may be inverted by arithmetic. This is **why OAEP/KEM exist** in the very next section.

# 2) Finite‑Field DH (FFDHE / DHE)

**Goal:** clean, interoperable DH key exchange using RFC‑7919 FFDHE groups with OpenSSL 3.x on Windows PowerShell, then derive an AEAD session key via HKDF and demo AES‑256‑GCM.

---

## 2.0 Quick correctness & security notes

* **Prefer named groups** (e.g., `ffdhe2048`) over ad‑hoc primes for speed & auditability.
* **Never reuse a (key, IV) pair in GCM.** Use a fresh 96‑bit IV per message.
* **HKDF salt**: this demo shows **no salt** (allowed by HKDF), but in practice use a random or transcript‑bound salt.
* **Ephemeral keys**: use fresh DH keypairs per session (DHE), not long‑term static DH.
* PowerShell helpers below avoid non‑portable hex conversions.

---

## 2.1 Generate shared parameters, keypairs & shared secret

### Option A (recommended): Use a named FFDHE group — no `dhparam` file needed

```powershell
[Environment]::CurrentDirectory = (Get-Location).Path

# Requires OpenSSL 3.x
# --- Client: DH keypair on RFC‑7919 group ffdhe2048 ---
openssl genpkey -algorithm DH -pkeyopt group:ffdhe2048 -out client_dh.pem
openssl pkey -in client_dh.pem -pubout -out client_dh_pub.pem

# --- Server: DH keypair on the SAME group ---
openssl genpkey -algorithm DH -pkeyopt group:ffdhe2048 -out server_dh.pem
openssl pkey -in server_dh.pem -pubout -out server_dh_pub.pem

# (Optional) Inspect public keys
openssl pkey -in client_dh_pub.pem -pubin -text -noout
openssl pkey -in server_dh_pub.pem -pubin -text -noout
```

### Option B: Generate a safe prime (legacy flow)

> Use only if you explicitly need custom parameters. Avoid `-dsaparam` (unsafe for DH key exchange).

```powershell
# Generate safe prime p and generator g (slow)
openssl dhparam -out ffdhe2048.pem 2048

# Verify parameters
openssl dhparam -in ffdhe2048.pem -text -check -noout

# Both sides derive keys from the same (p, g)
openssl genpkey -paramfile ffdhe2048.pem -out client_dh.pem
openssl pkey -in client_dh.pem -pubout -out client_dh_pub.pem

openssl genpkey -paramfile ffdhe2048.pem -out server_dh.pem
openssl pkey -in server_dh.pem -pubout -out server_dh_pub.pem
```

### Derive the shared secret `Z`

```powershell
# Derive Z on each side (raw big‑endian bytes)
openssl pkeyutl -derive -inkey client_dh.pem -peerkey server_dh_pub.pem -out Z_client.bin
openssl pkeyutl -derive -inkey server_dh.pem -peerkey client_dh_pub.pem -out Z_server.bin

# Verify equality
if ((Get-FileHash Z_client.bin).Hash -eq (Get-FileHash Z_server.bin).Hash) { 'Same Z' } else { 'Different' }

# Inspect (human‑readable)
Format-Hex .\Z_client.bin
```

---

## 2.2 HKDF → AES‑256‑GCM (no salt demo)

PowerShell helpers for robust hex conversion and binary writes:

```powershell
function Get-Hex([string]$Path) {
  [BitConverter]::ToString([IO.File]::ReadAllBytes($Path)).Replace('-', '').ToLower()
}
```

### (a) Bind context and derive a 32‑byte session key via HKDF(SHA‑256)

```powershell
[Environment]::CurrentDirectory = (Get-Location).Path
# Bind some context (transcript/info)
Set-Content -Path .\info.txt -Value 'NT219|FFDHE|demo' -NoNewline

# HKDF (no salt). OpenSSL writes binary to stdout → save as key.bin
openssl kdf -keylen 32 -binary `
  -kdfopt digest:SHA256 `
  -kdfopt mode:EXTRACT_AND_EXPAND `
  -kdfopt key:FILE:Z_client.bin `
  -kdfopt info:FILE:info.txt -out key.bin HKDF

$KEYHEX = Get-Hex 'key.bin'
$KEYHEX
```

> **Better practice:** add a salt, e.g. `-kdfopt salt:FILE:transcript_salt.bin` where `transcript_salt.bin` is fresh per session or derived from handshake data.

### (b) AES‑256‑GCM using Windows built‑in crypto (AesGcm) — no OpenSSL `enc`

```powershell
[Environment]::CurrentDirectory = (Get-Location).Path
Add-Type -AssemblyName System.Security

# Load key bytes derived above (32 bytes for AES‑256)
$key = [IO.File]::ReadAllBytes('key.bin')

# Create 12-byte IV
$iv = New-Object byte[] 12
# Create RNG object
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
# Fill IV with random bytes
$rng.GetBytes($iv)
# Save to file
[IO.File]::WriteAllBytes('iv.bin', $iv)


# Plaintext bytes (UTF‑8); or use ReadAllBytes for arbitrary data
$pt = [Text.Encoding]::UTF8.GetBytes('This is a secret over DHE.')
[IO.File]::WriteAllBytes('plain.txt', $pt)

# Allocate output buffers
$ct  = New-Object byte[] $pt.Length
$tag = New-Object byte[] 16  # 128‑bit tag
$aad = [byte[]]::new(0)      # optional AAD; keep empty for this demo

$aes = [System.Security.Cryptography.AesGcm]::new($key)
$aes.Encrypt($iv, $pt, $ct, $tag, $aad)

# Persist ciphertext and tag
[IO.File]::WriteAllBytes('ct.bin',  $ct)
[IO.File]::WriteAllBytes('tag.bin', $tag)

# Decrypt to verify
$pt2 = New-Object byte[] $ct.Length
$aes2 = [System.Security.Cryptography.AesGcm]::new($key)
$aes2.Decrypt($iv, $ct, $tag, $pt2, $aad)
[IO.File]::WriteAllBytes('dec.txt', $pt2)

if ((Get-FileHash plain.txt).Hash -eq (Get-FileHash dec.txt).Hash) { 'OK' } else { 'DIFF' }

```

---

## 2.3 Troubleshooting & gotchas

* **Mismatch groups/params** → `pkeyutl -derive` fails. Ensure both sides use **exactly** the same `group` (Option A) or the **same** `paramfile` (Option B).
* **OpenSSL version**: `openssl kdf` requires **3.x**. On 1.1.1 use another HKDF tool or a small script.
* **PowerShell hex**: avoid `Format-Hex` for values you need to pass back into OpenSSL; use the `Get-Hex` helper.
* **GCM IV reuse**: never reuse the same `(KEY, IV)`; if you need multiple messages, generate a new IV per message and include it with the ciphertext (e.g., prepend 12 bytes).
* **Key separation**: for bidirectional traffic, derive independent keys (e.g., HKDF `info:client→server` vs `server→client`).

---

# 3) ECDHE (named curve) — Client/Server

**Goal:** Agree on a **named curve** (like agreeing on `(p,g)` in FFDHE), verify support & parameters, then generate **ephemeral** EC keypairs and derive a shared secret `Z`. OpenSSL 3.x + PowerShell on Windows.

---

## 3.0 Quick notes

* **Negotiate a named curve first**: common choices are `prime256v1` (P‑256), `secp384r1` (P‑384), `secp521r1` (P‑521).
* Generate **ephemeral** keys per session (ECDHE), not long‑term static keys.
* Encode keys as **named_curve** (carry the curve OID), not explicit params, for protocol compatibility.
* Treat `Z` as secret; typically feed it to HKDF to get traffic keys (optional block provided).

---

## 3.1 Choose & verify the curve (before generating keys)

```powershell

# Check the list curves supporting by openssl
openssl ecparam -list_curves

# Choose the named curve (agreement between Client & Server)
# Safe options: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
$CURVE = 'prime256v1'   # change to 'secp384r1' or 'secp521r1' if desired

# Map to NIST label for cross-checking
$NistMap = @{ 'prime256v1'='P-256'; 'secp384r1'='P-384'; 'secp521r1'='P-521' }
$NIST = $NistMap[$CURVE]

# Check the OpenSSL build supports the curve
if (-not (openssl ecparam -list_curves | Select-String -SimpleMatch $CURVE)) {
  throw "Curve '$CURVE' is not supported by this OpenSSL build."
}

# (Optional) Dump explicit parameters (p, a, b, G, n, h) for reference
# Keys below will use named_curve encoding; this dump is for inspection only
openssl ecparam -name $CURVE -param_enc explicit -text -noout |
  Tee-Object -FilePath ("curve_{0}.txt" -f $CURVE)

```

---

## 3.2 Generate ephemeral keypairs on the agreed curve

```powershell
# --- Client keypair (named_curve encoding for protocol compatibility) ---
openssl genpkey -algorithm EC `
  -pkeyopt ec_paramgen_curve:$CURVE `
  -pkeyopt ec_param_enc:named_curve `
  -out client_ec.pem
openssl pkey -in client_ec.pem -pubout -out client_ec_pub.pem

# Verify the keys
openssl ec -in client_ec.pem -text -noout
openssl pkey -pubin -in client_ec_pub.pem -text -noout


# --- Server keypair ---
openssl genpkey -algorithm EC `
  -pkeyopt ec_paramgen_curve:$CURVE `
  -pkeyopt ec_param_enc:named_curve `
  -out server_ec.pem
openssl pkey -in server_ec.pem -pubout -out server_ec_pub.pem

# Verify the keys
openssl ec -in server_ec.pem -text -noout
openssl pkey -pubin -in server_ec_pub.pem -text -noout
```

---

## 3.3 Enforce & check curve parameters before derivation

```powershell
# Quick visual check (OID/NIST lines)
openssl pkey -in client_ec.pem -text -noout | Select-String 'ASN1 OID|NIST CURVE'
openssl pkey -in server_ec.pem -text -noout | Select-String 'ASN1 OID|NIST CURVE'


# Structural checks (private key consistency)
openssl pkey -in client_ec.pem -check -noout
openssl pkey -in server_ec.pem -check -noout

# Public key on-curve validation

openssl pkey -pubin -in client_ec_pub.pem -pubcheck -noout
openssl pkey -pubin -in server_ec_pub.pem -pubcheck -noout

```

---

## 3.4 Derive the shared secret (ECDHE)

```powershell

# Client uses Server public key
openssl pkeyutl -derive -inkey client_ec.pem -peerkey server_ec_pub.pem -out Z_ec_client.bin

# Server uses Client public key
openssl pkeyutl -derive -inkey server_ec.pem -peerkey client_ec_pub.pem -out Z_ec_server.bin

# Verify equality
if ((Get-FileHash Z_ec_client.bin).Hash -eq (Get-FileHash Z_ec_server.bin).Hash) { 'Same ECDH Z' } else { 'Different' }
Format-Hex .\Z_ec_client.bin
```

---

## 3.5 (Optional) Derive symmetric keys from Z using HKDF (SHA‑256)

```powershell
# Context binding (info); adjust to your transcript/session labels
Set-Content -Path .\info_ecdh.txt -Value 'NT219|ECDHE|demo' -NoNewline

# HKDF (no salt demo) → 32-byte key
openssl kdf -keylen 32 -binary `
  -kdfopt digest:SHA256 `
  -kdfopt mode:EXTRACT_AND_EXPAND `
  -kdfopt key:FILE:Z_ec_client.bin `
  -kdfopt info:FILE:info_ecdh.txt `
  -out key_ecdh.bin HKDF

# (Recommended) salted variant
# openssl kdf -keylen 32 -binary `
#   -kdfopt digest:SHA256 `
#   -kdfopt mode:EXTRACT_AND_EXPAND `
#   -kdfopt key:FILE:Z_ec_client.bin `
#   -kdfopt salt:hex:$( [BitConverter]::ToString((openssl rand 32).Split()).Replace('-', '').ToLower() ) `
#   -kdfopt info:FILE:info_ecdh.txt `
#   -out key_ecdh.bin HKDF
```

---

## 3.6 Troubleshooting

* **Curve mismatch** → `pkeyutl -derive` fails or produces different `Z`. Ensure both sides use the **same** `$CURVE`.
* **Unsupported curve** → verify with `ecparam -list_curves`.
* **Explicit vs named curve** → prefer `ec_param_enc:named_curve` for interoperability.
* **OpenSSL 3.x required** for `openssl kdf` HKDF CLI. On 1.1.1, use an HKDF helper script or library.

### 3.7 X25519

```powershell
# --- Client ---
openssl genpkey -algorithm X25519 -out client_x25519.pem
openssl pkey -in client_x25519.pem -pubout -out client_x25519_pub.pem

# --- Server ---
openssl genpkey -algorithm X25519 -out server_x25519.pem
openssl pkey -in server_x25519.pem -pubout -out server_x25519_pub.pem

# --- Derive shared secret ---
openssl pkeyutl -derive -inkey client_x25519.pem -peerkey server_x25519_pub.pem -out Z_x_client.bin
openssl pkeyutl -derive -inkey server_x25519.pem -peerkey client_x25519_pub.pem -out Z_x_server.bin

# --- Verify shared secret matches ---
if ((Get-FileHash Z_x_client.bin).Hash -eq (Get-FileHash Z_x_server.bin).Hash) {
    'Shared secret matches'
} else {
    'Shared secret differs'
}

# --- Optional: reject all-zero secret (some libs do this automatically) ---
if ((Get-Hex Z_x_client.bin) -match '^[0]+$') {
    'All-zero secret! (reject)'
} else {
    'Secret looks non-zero'
}

```

### 3.8 ECIES (ECDH + HKDF + AES‑GCM)

```powershell
# Recipient static (P-256)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out recip.pem
openssl pkey -in recip.pem -pubout -out recip_pub.pem

# Sender ephemeral
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out eph.pem
openssl pkey -in eph.pem -pubout -out eph_pub.pem

# ----- Sender -----
openssl pkeyutl -derive -inkey eph.pem -peerkey recip_pub.pem -out Z_sender.bin
Set-Content -NoNewline info_e.bin 'NT219|ECIES|demo'
openssl kdf -keylen 32 -binary `
  -kdfopt digest:SHA256 -kdfopt mode:EXTRACT_AND_EXPAND `
  -kdfopt key:FILE:Z_sender.bin -kdfopt info:FILE:info_e.bin > K_e.bin
$KEYHEX = Get-Hex K_e.bin
$IV = (openssl rand -hex 12).Trim()
Set-Content -NoNewline m.txt 'ECIES message'
$encOut = & openssl enc -aes-256-gcm -K $KEYHEX -iv $IV -in m.txt -out ct_e.bin -nosalt -p 2>&1
$TAG = ($encOut | Select-String -Pattern 'tag=').ToString().Split('=')[-1].Trim()

# ----- Recipient -----
openssl pkeyutl -derive -inkey recip.pem -peerkey eph_pub.pem -out Z_r.bin
openssl kdf -keylen 32 -binary `
  -kdfopt digest:SHA256 -kdfopt mode:EXTRACT_AND_EXPAND `
  -kdfopt key:FILE:Z_r.bin -kdfopt info:FILE:info_e.bin > K_r.bin
if ((Get-FileHash K_e.bin).Hash -eq (Get-FileHash K_r.bin).Hash) { 'KEM OK' } else { 'Mismatch' }
$null = & openssl enc -d -aes-256-gcm -K (Get-Hex K_r.bin) -iv $IV -in ct_e.bin -out m.dec -nosalt -p -tag $TAG 2>&1
if ((Get-FileHash m.txt).Hash -eq (Get-FileHash m.dec).Hash) { 'OK' } else { 'DIFF' }
```

---

## 4) TLS quick labs (PSK — no signatures)

```powershell
# External PSK (32 bytes hex) and identity
$PSK = (openssl rand -hex 32).Trim(); $ID = 'NT219-PSK'

# Start TLS 1.3 PSK server (no certificates/signatures)
Start-Process -WindowStyle Minimized -FilePath powershell -ArgumentList "-NoLogo -NoProfile -Command openssl s_server -accept 4444 -www -tls1_3 -psk_identity $ID -psk $PSK"

# Client connects with same PSK + identity
openssl s_client -connect 127.0.0.1:4444 -tls1_3 -psk_identity $ID -psk $PSK </nul
```

**Notes**
* Works without any certificate or signature algorithms.
* If your build also supports TLS 1.2 PSK, you can try: `-tls1_2 -cipher PSK-AES128-GCM-SHA256` on both sides.

---

## 5) Cleanup

```powershell
Remove-Item *.bin, *.txt, *.sig, ct*.bin, tag*.txt, m.dec -ErrorAction SilentlyContinue
```