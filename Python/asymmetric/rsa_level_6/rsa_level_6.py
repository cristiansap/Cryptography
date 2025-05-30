from Crypto.Util.number import long_to_bytes
from pwn import remote


conn = remote('130.192.5.212', 6646)

c = int(conn.recvline().strip().decode())
e = 65537

# The objective is the same as in rsa_level_5: I want to send c' = 2^e * c = 2^e * m^e = (2m)^e   =>  by sending c', I'm asking to the Oracle to encrypt the message 2m
# The difference this time is that I don't know the modulo 'n' but only the ciphertext 'c', so I have to ask to the server to encrypt 2 => the server is going to reply with 2^e mod n (that is what I need)
conn.sendline(b"e" + str(2).encode())
c_prime = int(conn.recvline().strip().decode())
c_prime = c_prime * c


conn.sendline(b"d" + str(c_prime).encode())     # first char: 'e' to encrypt, 'd' to decrypt
                                                # what you append after is what I want the Oracle to encrypt

m_doubled = int(conn.recvline().strip().decode())

m = m_doubled // 2

print("\nFLAG:", long_to_bytes(m).decode())
print()

conn.close()