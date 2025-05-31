from pwn import remote


conn = remote('130.192.5.212', 6562)

print()
print(conn.recvuntil(b"Want to encrypt? (y/n/f)").strip().decode())
print()
conn.sendline(b'y')     # send 'y' to encrypt a message
conn.recvuntil(b"> ").strip().decode()
conn.sendline(b'A'*46)  # a message UNDER MY CONTROL which is as long as the flag (namely 46B)
                        # => this is due to the fact that the length of the keystream must be exactly equal to the length of the flag that I will decrypt

encrypted_msg = conn.recvline().strip().decode()
print("Encrypted msg =", encrypted_msg)     # print the encrypted message


print()
print(conn.recvuntil(b"Want to encrypt something else? (y/n/f)").strip().decode())
print()
conn.sendline(b'f')     # send 'f' to get the encrypted flag
encrypted_flag = conn.recvline().strip().decode()
print("Encrypted flag =", encrypted_flag)     # print the encrypted flag


# NOTE: the flaw here is that the random number generator is seeded using int(time()), which only changes once per second.
#       This means that if two messages are encrypted within the same second, the same nonce is used !!!
#       Moreover, the starting key is fixed, it is never changing !!!
#       These vulnerabilities allow me to encrypt two different messages and recover both the plaintexts, but I have to be fast enough
#       to encrypt both messages within the same second.

# REASONING:
#            C1 = P1 ⊕ KeyStream
#            C2 = P2 ⊕ KeyStream
#         => a = C1 ⊕ C2 = P1 ⊕ P2
#         => flag = a ⊕ P2 = P1 ⊕ P2 ⊕ P2 = P1


encrypted_msg_bytes = bytes.fromhex(encrypted_msg)
encrypted_flag_bytes = bytes.fromhex(encrypted_flag)

plaintext = bytes([a ^ b for a, b in zip(encrypted_msg_bytes, encrypted_flag_bytes)])

recovered_flag = bytes([a ^ b for a, b in zip(plaintext, b'A' * 46)])

print("\nFlag:", recovered_flag.decode())
print()

conn.close()