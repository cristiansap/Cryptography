from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB

e = 65537
n = 176278749487742942508568320862050211633
print("N =", n)


f = FactorDB(n)
f.connect()

print("\nTry to factorize N:")  # get_factor_list() retrieve the 2 primes that factorize N only if the factorization is well known and stored in FactorDB archives
p = f.get_factor_list()[0]
q = f.get_factor_list()[1]

print("P =", p)
print("Q =", q)

print("\nTry to obtain 'd' starting from 'e' and 'N': ")
phi = (p-1) * (q-1)
d = pow(e, -1, phi)
print("d =", d)

c = 46228309104141229075992607107041922411

decrypted_msg = pow(c, d, n)
print("FLAG:", long_to_bytes(decrypted_msg).decode())
print()