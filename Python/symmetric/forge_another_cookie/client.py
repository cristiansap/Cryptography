from pwn import remote
from Crypto.Util.number import long_to_bytes, bytes_to_long


conn = remote('130.192.5.212', 6552)

conn.recvuntil(b"Username: ")

username = b"Cristia" + b"true" + (b"\x0c" * 12) + (b"\x0c" * 9)  # string construction: {'username=' + username} (16B in total) + {'true' + padding(12B)} (16B in total) + {padding(9B) + '&admin='} (16B in total)

# Block 0: 'username=Cristia'        -> 16 bytes
# Block 1: 'true' + padding (12B)    -> 16 bytes
# Block 2: padding (9B) + '&admin='  -> 16 bytes

# => Reconstruction: Block 0 + Block 2 + Block 1  <==>  "username=Cristia\x0c\x0c...\x0c&admin=true\x0c\x0c...\x0c"  <== wihout padding ==>  "username=Cristia&admin=true"


conn.sendline(username)
cookie = conn.recvline().decode()
print("\nEncrypted token:", cookie)

cookie_bytes = long_to_bytes(int(cookie))
forged_cookie = str(bytes_to_long(cookie_bytes[0:16] + cookie_bytes[32:48] + cookie_bytes[16:32]))

print("This is the forged cookie:", forged_cookie)

print()
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print()

conn.sendline(b"flag")      # tell to the server you want to get the flag

conn.sendline(forged_cookie.encode())

print(conn.recvline().strip().decode())


conn.close()