from pwn import remote


conn = remote('130.192.5.212', 6532)

for i in range(128):

    payload = b"A" * 32    # the OTP size is 32 (looking at the given code), so the input must be 32B long
    conn.sendline(payload.hex().encode())   # first time (send the payload to encrypt)
    conn.sendline(payload.hex().encode())   # second time (send the payload to encrypt)

    conn.recvuntil(b"Output: ")
    ciphertext1 = bytes.fromhex(conn.recvline().strip().decode())   # first time (receive the first ciphertext)

    conn.recvuntil(b"Output: ")
    ciphertext2 = bytes.fromhex(conn.recvline().strip().decode())   # second time (receive the second ciphertext)

    if ciphertext1 == ciphertext2:
        mode_guess = "ECB"
    else:
        mode_guess = "CBC"

    conn.sendline(mode_guess.encode())

    conn.recvline()   # skip the question "What mode did I use? (ECB, CBC)" -> I don't want to print it
    res = conn.recvline()
    print(f"[Round {i}] Guess: {mode_guess} - {res.decode()}")
    if b"Wrong" in res:
        print("Failure !!!")
        exit(-1)

print("Success!")
print(f"{conn.recvline().decode()}")    # print the flag

conn.close()
