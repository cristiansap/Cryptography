from pwn import remote
import json
import base64


conn = remote('130.192.5.212', 6521)

print()
print(conn.recvline().decode())
name = b"Cristiannnnnnnnn"  # choose a name in such a way that the plaintext_token is 32B long
conn.sendline(name)    # equal to write: conn.sendline(b"Cristian")

conn.recvuntil(b"This is your token: ")
cookie = conn.recvline().strip().decode()
print(f"This is your token: {cookie}\n")

print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print()

conn.sendline(b"flag")      # tell to the server you want to get the flag
print(conn.recvline().strip().decode())

# Starting from the full cookie, retrieve the nonce and the token
b64_nonce, b64_token = cookie.split(".")
enc_nonce = base64.b64decode(b64_nonce.encode())
enc_token = base64.b64decode(b64_token.encode())

plaintext_token = json.dumps({
    "username": name.decode()
})

# ChaCha20 is a cipher stream: (ciphertext = plaintext XOR keystream)
# so I can retrieve the keystream in this way: keystream = plaintext XOR ciphertext
keystream = bytes([n ^ t for (n,t) in zip(plaintext_token.encode(), enc_token)])

forged_token = json.dumps({
    "username": "C",   # I don't care about the username, it's not important, I only care about its length
    "admin": True
})

# Since the keystream is as long as the original plaintext_token, the forged_token must have the same length as the plaintext_token
if len(plaintext_token) != len(forged_token):
    print(f"\nThe two tokens must have the same length: {len(plaintext_token)}, {len(forged_token)}")

# Now I need to encrypt the forged_token to make it appear as it's the original one (on the server side, decryption is performed, so this step is mandatory)
enc_forged_token = bytes([p ^ k for p, k in zip(forged_token.encode(), keystream)])

# Reconstruct the forged cookie
# Note: the nonce (the first part of the cookie) should be the same as in the original cookie
forged_cookie = f"{base64.b64encode(enc_nonce).decode()}.{base64.b64encode(enc_forged_token).decode()}"

print(f"New token: {forged_cookie}\n")
conn.sendline(forged_cookie.encode())    # send the forged cookie to the server
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())  # print the flag

conn.close()