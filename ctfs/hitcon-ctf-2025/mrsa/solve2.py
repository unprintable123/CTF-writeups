from sage.all import *
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
import os


flag = os.environb.get(b"FLAG", b"flag{test_flag}")

n = getPrime(1024) * getPrime(1024)
k = 16
e = 65537

key = os.urandom(k * k)
M = matrix(Zmod(n), k, k, key)
C = M**e

aes = AES.new(key[:32], AES.MODE_CTR, nonce=key[-8:])
ct = aes.encrypt(flag)


# print(f"C = {C.list()}")
# print(f"{ct = }")

# print(C.charpoly())

# C = matrix(ZZ, C)
# M = matrix(ZZ, M)


F = Zmod(n, is_field=True)

p1 = C.charpoly()
R = PolynomialRing(F, 'x')
x = R.gen()

p1 = R(p1)
RI = R.quotient(p1)

xbar = RI(x)

def poly_xgcd(a, b):
    s, t, r = a._pari_with_name().gcdext(b._pari_with_name())
    s, t, r = map(R, (s, t, r))
    assert s * a + t * b == r
    return s, t, r

def R_inverse(poly):
    poly = poly.lift()
    s, t, r = poly_xgcd(p1, poly)
    if r.degree() != 0:
        print(r)
        raise ValueError("not invertible")
    return t / F(r)

vs = []
for i in range(k):
    v0 = C[i].list()
    v0[i] -= xbar
    v0 = [RI(v) for v in v0]
    vs.append(v0)

def scala_mul(s, v):
    return [RI(s) * vi for vi in v]

def vec_add(v1, v2):
    return [v1i + v2i for v1i, v2i in zip(v1, v2)]

def vec_mul(v1, v2):
    return sum(v1i * v2i for v1i, v2i in zip(v1, v2))

for i in range(k-1):
    vs[i] = scala_mul(R_inverse(vs[i][i]), vs[i])
    assert vs[i][i] == 1
    for j in range(i + 1, k):
        vs[j] = vec_add(vs[j], scala_mul(-vs[j][i], vs[i]))
        assert vs[j][i] == 0
assert vs[k-1][k-1] == 0

print(len(vs))

t0 = [None] * k
t0[-1] = RI(1)

for i in reversed(range(k-1)):
    t0[i] = -sum(vs[i][j] * t0[j] for j in range(i + 1, k))

for i in range(k):
    assert vec_mul(vs[i], t0) == 0
    assert vec_mul(C[i].list(), t0) == xbar * t0[i]

assert len(set(vec_mul(M[i].list(), t0) * R_inverse(t0[i]) for i in range(k))) == 1
