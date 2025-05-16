from pwn import remote
from binascii import unhexlify, hexlify
import hashpumpy


def read_menu(conn):
    # Read until the prompt "Choose an option (1-3): "
    data = conn.recvuntil(b"Choose an option (1-3): ")
    print("\n"+data.decode()+"\n")


conn = remote('130.192.5.212', 6630)

read_menu(conn)

conn.sendline(b"1")   # choose to enter a name
data = conn.recvuntil(b"Enter your name: ")
print(data.decode())

name = "Cristian"
conn.sendline(name.encode())
print(name+"\n")

conn.recvuntil(b"\n")

coupon = conn.recvline().decode().strip()
print(coupon)

coupon = coupon.split(":")[1].strip()
coupon_bytes = unhexlify(coupon.encode())
print("Coupon (in bytes):", coupon_bytes)

tag = conn.recvline().decode().strip()
tag = tag.split(":")[1].strip()
print("\nTAG:", tag)

print("\n---------- Lenght Extension Attack (using hashpumpy) ----------\n")

extra = b"&value=101"
secret_len = 16     # the server uses a 16 byte SECRET
new_tag, new_msg = hashpumpy.hashpump(tag, coupon_bytes, extra, secret_len)

print("NEW TAG:", new_tag)
print("NEW COUPON:", new_msg)


# read again the menu and select the operation number 2
read_menu(conn)
conn.sendline(b"2")   # choose to pay (later using the modified coupon)

conn.recvuntil(b"Enter your coupon: ")
conn.sendline(new_msg.hex().encode())

conn.recvuntil(b"Enter your MAC: ")
conn.sendline(new_tag.encode())


# Get the flag
print(conn.recvline().decode().strip())
print(conn.recvline().decode().strip())
print()

conn.close()