from pwn import remote
import string


conn = remote('130.192.5.212', 6541)

print()
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print(conn.recvline().strip().decode())
print()

flag = ""
i = 0

while True:
    pad = b"A" * (15 - i % 16)    # 16 => AES block size

    for guess in string.printable:
        conn.sendline(b"enc")
        conn.recvuntil(b"> ")

        block_number = i // 16

        if block_number == 0:
            data = pad + flag.encode() + guess.encode() + pad       # "AA...A" + flag (guessed so far) + guess (current char to guess) + "AA..A" + flag (shifted 1 byte at a time) 
        elif block_number == 1:
            data = flag.encode()[1+(i%16):] + guess.encode() + pad       # flag (guessed so far, starting from the 2nd char) + guess (current char to guess) + "AA..A" + flag (shifted 1 byte at a time) 
        elif block_number == 2:
            data = flag.encode()[17+(i%16):] + guess.encode() + pad      # flag (guessed so far, starting from the 17th char) + guess (current char to guess) + "AA..A" + flag (shifted 1 byte at a time) 


        conn.sendline(data.hex().encode())
        conn.recvuntil(b"> ")

        ciphertext = conn.recvline().strip().decode()
        ciphertext_bytes = bytes.fromhex(ciphertext)

        if ciphertext_bytes[0:16] == ciphertext_bytes[16*(block_number+1):16*(block_number+2)]:
            print("Char found:", guess)
            flag += guess
            break

    if flag[-1] == '}':     # exit when the last character of the flag is found
        break

    i += 1



print("\nThe flag is:", flag)

conn.close()