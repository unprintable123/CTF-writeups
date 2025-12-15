from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime
# from sage.all import *
# from pwn import *

p = getPrime(1024)

m = 1
for i in range(100):
    m *= (i+1)
print(m.bit_length())

def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

def get_next_prime(p, step):
    p+=step
    while not isPrime(p):
        p+=step
    return p

def test(n, e, d):
    ktot = d * e - 1
    t = ktot
    while t % 2 == 0:
        t //= 2
    passed = []

    for a in range(2, 100, 2):
        k = t
        cand = pow(a, k, n)
        while k < ktot:
            if cand != 1 and cand != (n - 1) and pow(cand, 2, n) == 1:
                p = gcd(cand - 1, n)
                passed.append(a)
                break
            k *= 2
            cand = (cand * cand) % n
    return passed

q = get_next_prime(p, m)

n = p * q
e = getPrime(64)
d = pow(e, -1, (p-1)*(q-1))



try:
    cipher = RSA.construct((n, e, d))
except:
    print("error!")

print(q%8)
print(test(n, e, d))

