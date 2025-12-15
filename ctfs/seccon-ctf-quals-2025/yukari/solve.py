from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime
from sage.all import *
# from pwn import *
import itertools

m = 1
for i in range(2, 100, 2):
    m = lcm(i, m)
print(m.bit_length())



def get_next_prime(p, step):
    p+=step
    while not isPrime(p):
        p+=step
    return p

def get_next_prime_zi(p, step):
    assert p % 4 == 1
    a, b = two_squares(p)
    for i in range(100):
        for j in range(100):
            if i == 0 and j == 0:
                continue
            a1 = a + i * step
            b1 = b + j * step
            q = a1 ** 2 + b1 ** 2
            if isPrime(q):
                return q

def iter_ids(n):
    if n <= 5:
        r = 10
    elif n <= 10:
        r = 5
    else:
        r = 2
    S = itertools.product(list(range(r)), repeat=n)
    S = sorted(S, key=lambda x: sum(x))
    for ids in S:
        if all(i==0 for i in ids):
            continue
        yield ids

def get_next_prime_zii(p, step):
    assert p % 8 == 1
    K = CyclotomicField(8)
    u = K.gen()
    facs = K.fractional_ideal(p).factor()
    ideal = facs[0][0]
    pi = ideal.gens_reduced()[0]
    pi_list = pi.list()
    for ids in iter_ids(len(pi_list)):
        new_pid = [u0 + v * step for u0, v in zip(pi_list, ids)]
        new_pi = K(new_pid)
        new_p = int(new_pi.norm())
        if isPrime(new_p):
            return new_p

def get_next_prime_ziii(p, step):
    assert p % 16 == 1
    K = CyclotomicField(16)
    u = K.gen()
    facs = K.fractional_ideal(p).factor()
    ideal = facs[0][0]
    pi = ideal.gens_reduced()[0]
    pi_list = pi.list()
    for ids in iter_ids(len(pi_list)):
        new_pid = [u0 + v * step for u0, v in zip(pi_list, ids)]
        new_pi = K(new_pid)
        new_p = int(new_pi.norm())
        if isPrime(new_p):
            return new_p




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


p = getPrime(1024)
while p % 16 != 1:
    p = getPrime(1024)

if p % 4 != 1:
    q = get_next_prime(p, m)
elif p % 8 ==5:
    q = get_next_prime_zi(p, m)
elif p % 16 == 9:
    q = get_next_prime_zii(p, m)
else:
    q = get_next_prime_ziii(p, m)

print(q.bit_length())

n = p * q
e = getPrime(64)
d = pow(e, -1, (p-1)*(q-1))

print(p % 32)
print(test(n, e, d))

