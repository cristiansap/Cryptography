from pwn import remote
from Crypto.Cipher import AES
import string


conn = remote('130.192.5.212', 6523)

print()
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print()

conn.recvuntil(b"> ")

conn.sendline(b"enc")   # ask for encryption

print(conn.recvline().strip().decode())

data = b"mynamesuperadmi?"      # I have to find a way to swap the last character ('?') with 'n' in order to generate the right string that unlocks the flag
print(data.decode()+"\n")
conn.sendline(data.hex().encode())

conn.recvuntil(b"IV: ")
iv = conn.recvline().strip().decode()

conn.recvuntil(b"Encrypted: ")
ciphertext = conn.recvline().strip().decode()

print("IV:", iv)
print("Ciphertext:", ciphertext)
print()


index = data.index(b'?') - AES.block_size
print("Index to modify:", index)    # index = -1 (namely the very last byte)
mask = ord(b'?') ^ ord(b'n')     # mask = XOR between the actual character and the desired one

edt_iv = bytearray(bytes.fromhex(iv))
edt_iv[index] = edt_iv[index] ^ mask       # change the IV

conn.recvuntil(b"> ")

conn.sendline(b"dec")   # ask for decryption
print(conn.recvline().strip().decode())

conn.sendline(ciphertext.encode())      # send the ciphertext
conn.recvuntil(b"> ")

conn.sendline(edt_iv.hex().encode())    # send the edited IV
conn.recvuntil(b"> ")

print(conn.recvline().strip().decode())     # get the flag
print()

conn.close()