#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime

with open("flag.txt", "r") as f:
    FLAG = f.read()

for _ in range(32):
    p = getPrime(1024)
    print("p =", p)

    q = int(input("q: "))
    assert p != q
    assert q.bit_length() >= 1024
    assert isPrime(q)

    n = p * q
    e = getPrime(64)
    d = pow(e, -1, (p - 1) * (q - 1))

    try:
        cipher = RSA.construct((n, e, d))
    except:
        print("error!")
        continue
    print("key setup successful")
    exit()

print(FLAG)
