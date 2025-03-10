from sage.all import *
from polynomial import fast_polynomial_gcd

p = ZZ(1208925819614629174706189)
R0 = PolynomialRing(GF(p), 'r')
r = R0.gen(0)

fs = ["outputs/result1/final.sobj", "outputs/result2/final.sobj", "outputs/result3/final.sobj"]
fs = []

f_poly = [load(f) for f in fs]
f_poly = [R0(f) for f in f_poly]

print([f.degree() for f in f_poly])


g = load("outputs/gcd.sobj")
# g = f_poly.pop()
while len(f_poly) > 0:
    f = f_poly.pop()
    g = fast_polynomial_gcd(g, f)
    print(g.degree())
save(g, "outputs/gcd.sobj")
print(g)


r = 221571505269605005502902
orig_samples = []
with open("output.txt", "r") as f:
    p, a, b = map(int, f.readline().strip().split())
    p = ZZ(int(p))
    EC = EllipticCurve(GF(p), [a, b])
    # print(p, a, b)
    for _ in range(1000):
        a, out = map(int, f.readline().strip().split())
        orig_samples.append((a, out))

a, out = orig_samples[0]
order = EC.order()
aK0 = EC.lift_x(ZZ(out-r))
K0 = aK0*(pow(a, -1, order))
print(K0)
a1, out1 = orig_samples[1]
assert ((a1*K0).x()+r)%p == out1

from hashlib import shake_128
from Crypto.Util.strxor import strxor
ctxt = bytes.fromhex("9a38ebbdbbd7b1bfa50fa5284c3af2fb01ba95b1224b58bae3cb75637297a35a176330a1acddf697da62724a")
keystream = shake_128(str((K0.x(), r)).encode()).digest(len(ctxt))
flag = strxor(keystream, ctxt)
print(flag)
