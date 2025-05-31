from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB


n = 770071954467068028952709005868206184906970777429465364126693
e = 3
ct = 388435672474892257936058543724812684332943095105091384265939   # ciphertext


f = FactorDB(n)
f.connect()

p1 = f.get_factor_list()[0]
p2 = f.get_factor_list()[1]
print("p1 =", p1)
print("p2 =", p2)

phi = (p1-1) * (p2-1)
d = pow(e, -1, phi)

decrypted_msg = pow(ct, d, n)

print("\nFLAG:", long_to_bytes(decrypted_msg).decode())
print()