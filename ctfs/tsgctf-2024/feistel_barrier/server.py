from hashlib import sha256
from Crypto.Util.number import getStrongPrime
import os
k = 1024//8
h_len = 32


def mgf(seed,mask_len):
    if mask_len > 2**32:
        raise ValueError("mask too long")
    t = b''
    for i in range(mask_len//h_len+1):
        t += sha256(seed + i.to_bytes(4, 'little')).digest()
    return t[:mask_len]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(data, e,n):
    if len(data) > k - 2*h_len - 2:
        raise ValueError("data too long")
    L = b""
    IHash = sha256(L).digest()
    PS = b"\x00" * (k - len(data) - 2*h_len - 2)
    DB = IHash + PS + b"\x01" + data
    seed = os.urandom(h_len)
    dbMask = mgf(seed, k - h_len -1)
    maskedDB = xor(DB, dbMask)
    seedMask = mgf(maskedDB, h_len)
    maskedSeed = xor(seed, seedMask)
    EM = b"\x00" + maskedSeed + maskedDB
    m = int.from_bytes(EM, 'big')


    c = pow(m, e, n)
    return c.to_bytes(k, 'big')

def decrypt(c,n,d):
    m = pow(int.from_bytes(c, 'big'), d, n)
    EM = m.to_bytes(k, 'big')
    return EM

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = pow(e, -1, phi)
flag = os.getenv("FLAG", "FAKECTF{THIS_IS_FAKE}")
flag = flag.encode()
chal = encrypt(flag, e, n)
print("n =", n)
print("e =", e)
print("chal =", chal.hex())


print("ciphertext:", end=" ")
c = input()
c = bytes.fromhex(c)
# if c == chal:
#     print("Challenge ciphertext will not be decrypted.")
print(decrypt(c,n,d).hex())