from pwn import remote


conn = remote('130.192.5.212', 6561)

print()
print(conn.recvline().strip().decode())
conn.sendline(b'123')

print(conn.recvline().strip().decode())
encrypted_secret = conn.recvline().strip().decode()
print(encrypted_secret)
print()

# NOTE: the flaw here is that the server encrypts all the messages using always the same nonce, BUT THE NONCE SHOULD BE USED ONLY ONCE !!!
#       Moreover, the starting key is fixed, it is never changing !!!
#       These vulnerabilities allow me to encrypt two different messages and recover both the plaintexts, since the keystream is always the same.

# REASONING:
#            C1 = P1 ⊕ KeyStream
#            C2 = P2 ⊕ KeyStream
#         => a = C1 ⊕ C2 = P1 ⊕ P2
#         => flag = a ⊕ P2 = P1 ⊕ P2 ⊕ P2 = P1

conn.recvuntil(b"Do you want to encrypt something else? (y/n)")
conn.sendline(b'y')     # ask for a second encryption
#print(conn.recvline().strip().decode())

conn.recvuntil(b"What is the message? ")
conn.sendline(b'A' * 46)    # a message UNDER MY CONTROL which is as long as the flag (namely 46B) 
                            # => this is due to the fact that the length of the keystream must be exactly equal to the length of the flag that I will decrypt
second_enc_message = conn.recvline().strip().decode()
print("Second encryption:")
print(second_enc_message)

encrypted_secret_bytes = bytes.fromhex(encrypted_secret)
second_enc_message_bytes = bytes.fromhex(second_enc_message)

plaintext = bytes([a ^ b for a, b in zip(encrypted_secret_bytes, second_enc_message_bytes)])

recovered_flag = bytes([p ^ m for p, m in zip(plaintext, b'A' * 46)])

print("\nFlag:", recovered_flag.decode())
print()

conn.close()