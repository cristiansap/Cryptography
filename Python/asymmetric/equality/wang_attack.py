# encoding: utf-8
import random
import struct
import time
import re
from Crypto.Hash import MD4

# Little-endian 32-bit words
def Endian(b: bytes):
    return [struct.unpack('<I', b[i:i+4])[0] for i in range(0, len(b), 4)]

# Circular left/right rotations
def LeftRot(n, b): return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff
def RightRot(n, b): return ((n >> b) | ((n & 0xffffffff) << (32 - b))) & 0xffffffff

# MD4 boolean functions
def F(x, y, z): return (x & y) | (~x & z)
def G(x, y, z): return (x & y) | (x & z) | (y & z)
def H(x, y, z): return x ^ y ^ z

def FF(a, b, c, d, k, s, X):
    return LeftRot((a + F(b, c, d) + X[k]) & 0xffffffff, s)

def GG(a, b, c, d, k, s, X):
    return LeftRot((a + G(b, c, d) + X[k] + 0x5a827999) & 0xffffffff, s)

def HH(a, b, c, d, k, s, X):
    return LeftRot((a + H(b, c, d) + X[k] + 0x6ed9eba1) & 0xffffffff, s)

# Compute MD4 digest
def MD4_hash(m: bytes) -> str:
    h = MD4.new()
    h.update(m)
    return h.hexdigest()

# First-round differential step
def FirstRound(abcd, j, i, s, X, constraints):
    v = LeftRot((abcd[j%4] + F(abcd[(j+1)%4], abcd[(j+2)%4], abcd[(j+3)%4]) + X[i]) & 0xffffffff, s)
    for constraint in constraints:
        bit = constraint[1]
        if constraint[0] == '=':
            v ^= (v ^ abcd[(j+1)%4]) & (1 << bit)
        elif constraint[0] == '0':
            v &= ~(1 << bit)
        elif constraint[0] == '1':
            v |= (1 << bit)
    # invert to update X[i]
    X[i] = (RightRot(v, s) - abcd[j%4] - F(abcd[(j+1)%4], abcd[(j+2)%4], abcd[(j+3)%4])) & 0xffffffff
    abcd[j%4] = v

# Differential collision finder (first-round sketch)
def FindCollision(block: bytes):
    X = Endian(block)
    initial_abcd = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    abcd = initial_abcd.copy()

    # First-round constraints (Wang)
    constraints = [
        [['=', 6]], [['0', 6], ['=', 7], ['=', 10]],
        [['1', 6], ['1', 7], ['0', 10], ['=', 25]],
        [['1', 6], ['0', 7], ['0', 10], ['0', 25]],
        [['1', 7], ['1', 10], ['0', 25], ['=', 13]],
        [['0', 13], ['=', 18], ['=', 19], ['=', 20], ['=', 21], ['1', 25]],
        [['=', 12], ['0', 13], ['=', 14], ['0', 18], ['0', 19], ['1', 20], ['0', 21]],
        [['1', 12], ['1', 13], ['0', 14], ['=', 16], ['0', 18], ['0', 19], ['0', 20], ['0', 21]],
        [['1', 12], ['1', 13], ['1', 14], ['0', 16], ['0', 18], ['0', 19], ['0', 20], ['=', 22], ['1', 21], ['=', 25]],
        [['1', 12], ['1', 13], ['1', 14], ['0', 16], ['0', 19], ['1', 20], ['1', 21], ['0', 22], ['1', 25], ['=', 29]],
        [['1', 16], ['0', 19], ['0', 20], ['0', 21], ['0', 22], ['0', 25], ['1', 29], ['=', 31]],
        [['0', 19], ['1', 20], ['1', 21], ['=', 22], ['1', 25], ['0', 29], ['0', 31]],
        [['0', 22], ['0', 25], ['=', 26], ['=', 28], ['1', 29], ['0', 31]],
        [['0', 22], ['0', 25], ['1', 26], ['1', 28], ['0', 29], ['1', 31]],
        [['=', 18], ['1', 22], ['1', 25], ['0', 26], ['0', 28], ['0', 29]],
        [['0', 18], ['=', 25], ['1', 26], ['1', 28], ['0', 29], ['=', 31]]
    ]
    shift = [3, 7, 11, 19] * 4
    change = [0, 3, 2, 1] * 4

    # Apply first-round constraints
    for i in range(16):
        FirstRound(abcd, change[i], i, shift[i], X, constraints[i])

    # Create the collided block
    def CreateCollision(m: bytes) -> bytes:
        Xc = Endian(m)
        Xc[1] = (Xc[1] + (1 << 31)) & 0xffffffff
        Xc[2] = (Xc[2] + ((1 << 31) - (1 << 28))) & 0xffffffff
        Xc[12] = (Xc[12] - (1 << 16)) & 0xffffffff
        return b''.join(struct.pack('<I', w) for w in Xc)

    m1 = block
    m2 = CreateCollision(m1)
    if MD4_hash(m1) == MD4_hash(m2):
        return m1, m2
    return None, None

# Main
if __name__ == '__main__':
    start = time.perf_counter()
    print('[+] Finding Collision...')
    while True:
        block = bytes(random.getrandbits(8) for _ in range(64))
        c1, c2 = FindCollision(block)
        if c1:
            h1 = MD4_hash(c1)
            break

    hex1 = c1.hex()
    hex2 = c2.hex()
    diffs = [(hex1[i:i+8], hex2[i:i+8]) for i in range(0, len(hex1), 8) if hex1[i:i+8] != hex2[i:i+8]]

    print(f'[-] M1: {hex1}')
    print(f'[-] M2: {hex2}')
    print(f'[-] MD4: {h1}')
    print(f'[-] Differences: {diffs}')
    print(f'[!] Timer: {round(time.perf_counter() - start, 2)}s')
