from Crypto.Util.number import long_to_bytes
from pwn import remote


conn = remote('130.192.5.212', 6645)

n = int(conn.recvline().strip().decode())
c = int(conn.recvline().strip().decode())
e = 65537

# I send c' = 2^e * c = 2^e * m^e = (2m)^e   =>  by sending c', I'm asking to the Oracle to encrypt the message 2m
c_prime = pow(2, e, n) * c

conn.sendline(b"d" + str(c_prime).encode())     # first char: 'e' to encrypt, 'd' to decrypt
                                                # what you append after is what I want the Oracle to encrypt

m_doubled = int(conn.recvline().strip().decode())

m = m_doubled // 2

print("\nFLAG:", long_to_bytes(m).decode())
print()