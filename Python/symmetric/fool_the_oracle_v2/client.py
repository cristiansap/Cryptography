from pwn import remote
from Crypto.Random import get_random_bytes
import string


conn = remote('130.192.5.212', 6542)

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
    random_padding = get_random_bytes(11)    # now I need a random padding which is 11B long so that the first block that the server creates generating 5B of random padding is completely filled

    for guess in string.printable:
        conn.sendline(b"enc")
        conn.recvuntil(b"> ")

        block_number = i // 16

        if block_number == 0:
            data = random_padding + pad + flag.encode() + guess.encode() + pad         # random padding + "AA...A" + flag (guessed so far) + guess (current char to guess) + "AA..A" + flag (shifted 1 byte at a time) 
        elif block_number == 1:
            data = random_padding + flag.encode()[1+(i%16):] + guess.encode() + pad    # random padding + flag (guessed so far, starting from the 2nd char) + guess (current char to guess) + "AA..A" + flag (shifted 1 byte at a time) 
        elif block_number == 2:
            data = random_padding + flag.encode()[17+(i%16):] + guess.encode() + pad   # random padding + flag (guessed so far, starting from the 17th char) + guess (current char to guess) + "AA..A" + flag (shifted 1 byte at a time) 

        # REMARK:   if block_number == 1, 'data' includes the flag guessed so far starting from the 2nd char because the first block (16B) has already been guessed, then in order to have one free position, I only take from the 2nd to the 16th guessed char so that the 17th char of the flag is shifted to the left and can be now guessed
        # REMARK_2: if block_number == 2, the concept remains the same, but with the difference that now the first TWO blocks (16B + 16B) has already been guessed

        conn.sendline(data.hex().encode())
        conn.recvuntil(b"> ")

        ciphertext = conn.recvline().strip().decode()
        ciphertext_bytes = bytes.fromhex(ciphertext)

        if ciphertext_bytes[16:32] == ciphertext_bytes[16*(block_number+2):16*(block_number+3)]:    # the comparison is now always made between the second block and another block (depending on which block of flag I'm discovering)
            print("Char found:", guess)
            flag += guess
            break

    if flag[-1] == '}':     # exit when the last character of the flag is found
        break

    i += 1



print("\nThe flag is:", flag)

conn.close()