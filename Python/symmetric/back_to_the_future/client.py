from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
import requests


def days_to_seconds(days):
    return days * 24 * 60 * 60


session = requests.Session()
now = int(time.time())

# Request a cookie with admin=1
res = session.get("http://130.192.5.212:6522/login?username=cris&admin=1")
info = res.json()

# Retrieve the encrypted nonce and cookie
nonce = info["nonce"]
encrypted_cookie = long_to_bytes(info["cookie"])

# Compute the original "expires" field (30 days after "now")
original_expires = str(now + days_to_seconds(30)).encode()

# Retrieve the encrypted "expires" field from the encrypted cookie
encrypted_expires = encrypted_cookie[22:32]

# Retrieve the keystream (this is a keystream reuse attack)
keystream = bytes([a ^ b for a, b in zip(original_expires, encrypted_expires)])

for delay in range(32, 289):    # expires - admin_expire_date = (now + delay) - (now - r) = (delay + r) ∈ [291, 299]  [where r = rand(10, 259)]
                                # => since (delay + r) ∈ [291, 299]  and  r = rand(10, 259) => delay range: [291-259, 299-10] = [32, 289]
    
    # Try to build a plaintext date that matches the server-side control using different 'delay' values
    forged_original_expires = str(now + days_to_seconds(delay)).encode()

    forged_expires = bytes([a ^ b for a, b in zip(forged_original_expires, keystream)])

    forged_cookie = encrypted_cookie[:22] + forged_expires + encrypted_cookie[32:]
    forged_cookie = bytes_to_long(forged_cookie)

    res = session.get(f"http://130.192.5.212:6522/flag?nonce={nonce}&cookie={forged_cookie}")
    if (res.content != b"You have expired!"):
        print(res.content)
        break