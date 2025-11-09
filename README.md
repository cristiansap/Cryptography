# Cryptography CTFs

## Collection of write-ups & challenge implementations

This repository contains write-ups and implementations of Cryptography CTF challenges. It documents a variety of cryptographic attacks and scripts used for learning.

---

## Languages & Libraries
- **C** — challenge implementations and experiments using **OpenSSL** (big numbers, digests, encryption, random numbers).
- **Python** — exploit and analysis scripts using **PyCryptodome**.

---

## Covered categories
The repo is organized by attack category. Each folder contains the problems and their solutions.

### Symmetric ciphers
Implemented / demonstrated attacks:
- **Bit flipping** (tampering ciphertexts to alter plaintext in predictable ways)  
- **Adaptive Chosen-Plaintext Attack**  
- **CBC Padding Oracle** (padding oracle attacks against CBC-mode)  
- **Keystream reuse** (vulnerabilities from reusing stream cipher keystreams)  
- **Frequency analysis** (classical statistical attacks)

### Asymmetric ciphers (RSA)
Implemented attacks:
- **Factorization** (basic factoring methods)  
- **Fermat's factorization** (efficient when prime factors are close)  
- **Common modulus attack** (same modulus, different exponents)  
- **Common prime attacks** (shared prime factors across keys)  
- **Hastad’s broadcast attack** (low-exponent broadcast vulnerability)  
- **Low public exponent attacks** (issues with small *e* values)  
- **LSB oracle**

### Hash functions
Implemented attacks:
- **Length extension attacks** (for iterative hash constructions like MD5/SHA family)  
- **Wang attack for collisions** — against MD4.

---

## OpenSSL practice exercises
Some CTFs included here were used to practice with OpenSSL:
- **Big number (BN)** operations
- **Digest** creation / verification
- **Encryption** primitives and modes
- **Random number** generation and operations
