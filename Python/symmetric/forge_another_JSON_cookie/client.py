from pwn import remote
from Crypto.Cipher import AES
import json
import base64


conn = remote('130.192.5.212', 6551)

BLOCK_SIZE = AES.block_size

username = b'{"username": "'
admin = b'", "admin": '
true = b'true,'
field = b'field'

fill_block = b'A' * (BLOCK_SIZE - len(username))   # fill the first block
block1 = true + b' ' * (BLOCK_SIZE - len(true))
block2 = b' ' * (BLOCK_SIZE - 1) + b'"'   # the character '"' is automatically escaped by json.dumps() with '\' => final result: '\"' 
block3 = b' ' * (BLOCK_SIZE - 1)    # hence this block will contain: '"' + 15 spaces (while the previous block ends with '\')
                                    # so I can use this block to enclose the field 'field' with the double quotes
block4 = field + b' ' * (BLOCK_SIZE - len(field))
block5 = b':' + b' ' * (BLOCK_SIZE - 1)
admin_block = b'A' * (BLOCK_SIZE - len(admin))  # this block contains the string '"admin": ' at the end, so that I can append the encrypted block of the string 'true,' (i.e. block1) just after it

data = fill_block + block1 + block2 + block3 + block4 + block5 + admin_block

# Try to emulate what is happening at server side
json_dump = json.dumps({
    "username": data.decode(),
    "admin": False
})
print("\n---Original json dump---\n" + json_dump)


# Print the content of all blocks for clarity
print("\n---BLOCKS---")
for i in range((len(json_dump) // BLOCK_SIZE) + 1):
    print(f"BLOCK [{i*BLOCK_SIZE}:{(i+1)*BLOCK_SIZE}] =", json_dump[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE])


print("\n---Rearranged json dump---")
print(json_dump[0:16] + json_dump[96:112] + json_dump[16:32] + json_dump[48:64] + json_dump[64:80] + json_dump[48:64] + json_dump[80:96] + json_dump[112:128])

# NOTE: the rearrangement of blocks printed above is exactly the one I have to use once the blocks are encrypted.
# This is the printed content:
# {"username": "AAAAAA", "admin": true,           "               field           "               :               false}

conn.recvuntil(b"Hi, please tell me your name!\n> ")
conn.sendline(data)

# Obtain the token from the server
conn.recvuntil(b"This is your token: ")
token = base64.b64decode(conn.recvline().strip().decode())
#print("\nEncrypted token:", token)

# Use the same block arrangement as printed above with json_dump
forged_token = token[0:16] + token[96:112] + token[16:32] + token[48:64] + token[64:80] + token[48:64] + token[80:96] + token[112:128]
forged_token = base64.b64encode(forged_token).decode()


print()
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print()


conn.recvuntil(b"> ")
conn.sendline(b"flag")      # tell to the server to send the flag

conn.recvuntil(b"What is your token?\n> ")
conn.sendline(forged_token.encode())

print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print()

conn.close()