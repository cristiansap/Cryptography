from pwn import remote


conn = remote('130.192.5.212', 6631)

# Collision found by the professor in the videolecture by running the 
m1 = 'f4bf625ccd653c06b556939f5e1c2841565ce6c2d17f38dfd96b2620891dfeaa2de86cdef84fd9f5415ad71307af279fc473e988ae5405d3aa064540f33d35a1'
m2 = 'f4bf625ccd653c86b556930f5e1c2841565ce6c2d17f38dfd96b2620891dfeaa2de86cdef84fd9f5415ad71307af279fc473e888ae5405d3aa064540f33d35a1'

print()
print((conn.recvline().strip().decode()))
print()

conn.recvuntil(b"Enter the first string: ")
conn.sendline(m1.encode())

conn.recvuntil(b"Enter your second string: ")
conn.sendline(m2.encode())

print((conn.recvline().strip().decode()))
print()