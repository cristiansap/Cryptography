import numpy as np
import string
from Crypto.Util.strxor import strxor


CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
    'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
    'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
    'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
    'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}


with open("hacker-manifesto.enc", "r") as f:
    encrypted_lines_hex = f.read().splitlines()
    encrypted_lines_bytes = [bytes.fromhex(line) for line in encrypted_lines_hex]

max_len = max(len(line) for line in encrypted_lines_bytes)


# REMARK: the idea is:
# - All lines have been encrypted using the same ChaCha20 key and nonce, so they share the same keystream.
# - XORing different ciphertexts reveals the XOR of their plaintexts (since the same keystream was used).
# - By guessing likely characters (e.g., space, common letters) and checking if the result is printable, I can infer parts of the keystream.
# - By looking at the decrypted content, manual adjustments can be applied to improve the decryption of the rest of the content.
# - Once enough of the keystream is recovered, I decrypt all ciphertexts.
# - Then the flag can be identified from the recovered plaintexts trying to interpret the decrypted content.

keystream = bytearray()

# For each byte position in the ciphertext
for i in range(max_len):
    freqs = np.zeros(256)

    # For every possible byte of the keystream
    for guessed_key_byte in range(256):
        score = 0.0
        for ciphtxt in encrypted_lines_bytes:
            if i >= len(ciphtxt):
                continue
            decrypted_char = ciphtxt[i] ^ guessed_key_byte
            if 32 <= decrypted_char <= 126:    # if 'decrypted_char' is a printable character
                score += CHARACTER_FREQ.get(chr(decrypted_char).lower(), 0)
        freqs[guessed_key_byte] = score

    # Select the byte with the highest score
    best_guess = int(np.argmax(freqs))
    keystream.append(best_guess)


# Manual adjustments to the keystream
dec = keystream[28] ^ encrypted_lines_bytes[3][28]
mask = dec ^ ord('Y')
keystream[28] = keystream[28] ^ mask

dec = keystream[65] ^ encrypted_lines_bytes[1][65]
mask = dec ^ ord('h')
keystream[65] = keystream[65] ^ mask

dec = keystream[67] ^ encrypted_lines_bytes[1][67]
mask = dec ^ ord('u')
keystream[67] = keystream[67] ^ mask

dec = keystream[53] ^ encrypted_lines_bytes[6][53]
mask = dec ^ ord('n')
keystream[53] = keystream[53] ^ mask

dec = keystream[57] ^ encrypted_lines_bytes[6][57]
mask = dec ^ ord('o')
keystream[57] = keystream[57] ^ mask

dec = keystream[34] ^ encrypted_lines_bytes[1][34]
mask = dec ^ ord(' ')
keystream[34] = keystream[34] ^ mask

dec = keystream[49] ^ encrypted_lines_bytes[5][49]
mask = dec ^ ord('b')
keystream[49] = keystream[49] ^ mask

dec = keystream[17] ^ encrypted_lines_bytes[4][17]
mask = dec ^ ord('s')
keystream[17] = keystream[17] ^ mask

dec = keystream[20] ^ encrypted_lines_bytes[4][20]
mask = dec ^ ord('w')
keystream[20] = keystream[20] ^ mask

dec = keystream[23] ^ encrypted_lines_bytes[4][23]
mask = dec ^ ord('h')
keystream[23] = keystream[23] ^ mask

dec = keystream[37] ^ encrypted_lines_bytes[4][37]
mask = dec ^ ord('r')
keystream[37] = keystream[37] ^ mask

dec = keystream[57] ^ encrypted_lines_bytes[4][57]
mask = dec ^ ord('t')
keystream[57] = keystream[57] ^ mask

dec = keystream[38] ^ encrypted_lines_bytes[5][38]
mask = dec ^ ord('i')
keystream[38] = keystream[38] ^ mask

dec = keystream[40] ^ encrypted_lines_bytes[5][40]
mask = dec ^ ord('a')
keystream[40] = keystream[40] ^ mask

dec = keystream[43] ^ encrypted_lines_bytes[5][43]
mask = dec ^ ord(' ')
keystream[43] = keystream[43] ^ mask

dec = keystream[43] ^ encrypted_lines_bytes[1][43]
mask = dec ^ ord('e')
keystream[43] = keystream[43] ^ mask

dec = keystream[45] ^ encrypted_lines_bytes[1][45]
mask = dec ^ ord('a')
keystream[45] = keystream[45] ^ mask

dec = keystream[46] ^ encrypted_lines_bytes[1][46]
mask = dec ^ ord('l')
keystream[46] = keystream[46] ^ mask

dec = keystream[58] ^ encrypted_lines_bytes[1][58]
mask = dec ^ ord('i')
keystream[58] = keystream[58] ^ mask

dec = keystream[59] ^ encrypted_lines_bytes[1][59]
mask = dec ^ ord('n')
keystream[59] = keystream[59] ^ mask


# Decrypt all the rows
print("=== Decrypted output ===\n")
for ciphtxt in encrypted_lines_bytes:
    l = min(len(ciphtxt), len(keystream))
    decrypted = strxor(ciphtxt[:l], keystream[:l])
    printable = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in decrypted)   # non-printable characters are replaced with '.'
    print(printable)

