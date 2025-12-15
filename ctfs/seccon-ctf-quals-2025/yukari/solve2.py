from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime
from sage.all import *
from pwn import *
from tqdm import tqdm
import itertools

# io = process(['python3', 'chal.py'])
# nc yukari-infinity.seccon.games 13910
# io = remote('yukari-infinity.seccon.games', 13910)
# nc yukari.seccon.games 15809
io = remote('yukari.seccon.games', 15809)

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

K8 = CyclotomicField(8)
def get_next_prime_zii(p, step):
    assert p % 8 == 1
    facs = K8.fractional_ideal(p).factor()
    ideal = facs[0][0]
    pi = ideal.gens_reduced()[0]
    pi_list = pi.list()
    for ids in iter_ids(len(pi_list)):
        new_pid = [u0 + v * step for u0, v in zip(pi_list, ids)]
        new_pi = K8(new_pid)
        new_p = int(new_pi.norm())
        if isPrime(new_p):
            return new_p

K16 = CyclotomicField(16)
def get_next_prime_ziii(p, step):
    assert p % 16 == 1
    facs = K16.fractional_ideal(p).factor()
    ideal = facs[0][0]
    pi = ideal.gens_reduced()[0]
    pi_list = pi.list()
    for ids in iter_ids(len(pi_list)):
        new_pid = [u0 + v * step for u0, v in zip(pi_list, ids)]
        new_pi = K16(new_pid)
        new_p = int(new_pi.norm())
        if isPrime(new_p) and test(p, new_p):
            return new_p


def test(p, q):
    n = p * q
    ktot = (p - 1) * (q - 1)
    t = ktot
    while t % 2 == 0:
        t //= 2
    for a in range(2, 100, 2):
        k = t
        cand = pow(a, k, n)
        while k < ktot:
            if cand != 1 and cand != (n - 1) and pow(cand, 2, n) == 1:
                p = gcd(cand - 1, n)
                assert p > 1
                return False
            k *= 2
            cand = (cand * cand) % n
    return True

def solve(p):
    print(p%16)
    if p % 4 != 1:
        q = get_next_prime(p, m)
    elif p % 8 ==5:
        q = get_next_prime_zi(p, m)
    elif p % 16 == 9:
        q = get_next_prime_zii(p, m)
    else:
        q = get_next_prime_ziii(p, m)
    return q

for _ in tqdm(range(32)):
    io.recvuntil('p = ')
    p = int(io.recvline())
    q = solve(p)
    print(test(p, q))
    io.sendline(str(q).encode())

io.interactive()
