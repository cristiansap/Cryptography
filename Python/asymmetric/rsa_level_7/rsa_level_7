from Crypto.Util.number import long_to_bytes
from pwn import remote


def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")


conn = remote('130.192.5.212', 6647)

n = int(conn.recvline().strip().decode())
c = int(conn.recvline().strip().decode())
e = 65537


# REMARK: by looking at what is printed in the last line of code (file 'chall.py'), it immediately
#         stands out that I have to perform the LSB Oracle attack by observing the LSB of the message 2m.
#         In fact, the operation dec % 2 provides the information whether the LSB is 0 or 1.


# init the bounds
upper_bound = n
lower_bound = 0

# loop
factor = 2
for i in range(n.bit_length()):
    c_prime = pow(factor, e, n) * c
    factor *= 2

    # interact with the server
    conn.sendline(str(c_prime).encode())
    bit = int(conn.recvline().strip().decode())

    # update bounds based on the leaked LSB
    if bit == 1:
        lower_bound = (upper_bound + lower_bound) // 2
    else:
        upper_bound = (upper_bound + lower_bound) // 2
    
    print_bounds(lower_bound, upper_bound)


print("\nFLAG:", long_to_bytes(lower_bound).decode())
print()