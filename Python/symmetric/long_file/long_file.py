from base64 import b64decode
import numpy as np
from Crypto.Util.strxor import strxor

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}


# NOTE: The server is always using the same key and the same nonce => mount a keystream reuse attack !!!

# The idea is:
# - All lines have been encrypted using the same ChaCha20 key and nonce, so they share the same keystream.
# - XORing different ciphertexts reveals the XOR of their plaintexts (since the same keystream was used).
# - By guessing likely characters (e.g., space, common letters) and checking if the result is printable, I can infer parts of the keystream.
# - By looking at the decrypted content, manual adjustments can be applied to improve the decryption of the rest of the content.
# - Once enough of the keystream is recovered, I decrypt all ciphertexts.
# - Then the flag can be identified from the recovered plaintexts trying to interpret the decrypted content.


KEYSTREAM_SIZE = 1000

# Read the file (KEYSTREAM_SIZE byte at a time)
ciphertexts = []
with open("./file.enc", "rb") as f:
    while True:
        ciphtxt = f.read(KEYSTREAM_SIZE)
        if not ciphtxt:
            break
        ciphertexts.append(ciphtxt)

max_len = max(len(c) for c in ciphertexts)
min_len = min(len(c) for c in ciphertexts)

keystream = bytearray()

candidates_list = []

# For each byte position in the ciphertext
for i in range(max_len):
    freqs = np.zeros(256, dtype=float)

    # For every possible byte of the keystream
    for guess_byte in range(256):
        for c in ciphertexts:
            if i >= len(c):
                continue
            decrypted_char = c[i] ^ guess_byte
            if 32 <= decrypted_char <= 126:    # if 'decrypted_char' is a printable character
                freqs[guess_byte] += CHARACTER_FREQ.get(chr(decrypted_char).lower(), 0)

    # Select the byte with the highest score
    best_guess = int(np.argmax(freqs))
    keystream.append(best_guess)


# Decrypt all the rows and find the one containing the flag
for c in ciphertexts:
    l = min(len(c), len(keystream))
    decrypted = strxor(c[:l], keystream[:l])
    printable = str(decrypted)
    if "CRYPTO25" in printable:
        print("\n=== Decrypted output ===\n")
        print(printable + "\n")
        break