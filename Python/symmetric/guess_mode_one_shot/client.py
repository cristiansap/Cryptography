from pwn import remote

def xor_bytes(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

def build_input(otp):
    # I want data ^ otp to result in two equal blocks
    input = b"A" * 32    # the OTP size is 32 (looking at the given code), so the input must be 32B long
    data = xor_bytes(input, otp)
    return data


conn = remote('130.192.5.212', 6531)

for i in range(128):
    conn.recvuntil(b"The otp I'm using: ")
    otp_line = conn.recvline().strip().decode()   # decode(): from bytes to string
    otp = bytes.fromhex(otp_line)  # from hex to bytes (to compute the XOR)

    payload = build_input(otp)
    conn.sendline(payload.hex().encode())   # hex() is needed since the server wants the input to be in hexadecimal format (looking at the server code, he's using bytes.fromhex())

    conn.recvuntil(b"Output: ")
    ciphertext = bytes.fromhex(conn.recvline().strip().decode())

    if ciphertext[0:16] == ciphertext[16:32]:
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
