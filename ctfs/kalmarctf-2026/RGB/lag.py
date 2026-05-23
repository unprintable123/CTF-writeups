from sage.all import *
from tqdm import tqdm, trange
import sys
import json
import time

p = 110878580464934402421519766750253673622313
q = 142494346453810376391409508907483524822863
N = p * q

F = GF(q)
H = PolynomialRing(F, "R")
R = H.gen()
def fast_lagrange(ys):

    fact = [F(1)]
    while len(fact) < len(ys):
        fact.append(fact[-1] * len(fact))

    def solve(xs, ys):
        def comp(xs, ys, bounds):
            start, end, sign = bounds[0], bounds[-1], (-1)**len(bounds)
            if xs[0] > start:
                return [y*fact[x-end-1]/fact[x-start] for x, y in zip(xs, ys)]
            else:
                return [y*fact[start-x-1]/fact[end-x]*sign for x, y in zip(xs, ys)]
        
        if len(ys) == 1:
            return ys[0], R-xs[0]
    
        xs1, xs2 = xs[:len(xs)//2], xs[len(xs)//2:]
        ys1, ys2 = ys[:len(ys)//2], ys[len(ys)//2:]
    
        ys1 = comp(xs1, ys1, xs2)
        ys2 = comp(xs2, ys2, xs1)
        f1, prod1 = solve(xs1, ys1)
        f2, prod2 = solve(xs2, ys2)
        return f1*prod2 + f2*prod1, prod1*prod2

    return solve(range(1, len(ys) + 1), ys)[0]

def remove_trailing_zeros(f):
    num_zeros = 0
    i = 0
    while i <= f.degree() and f[i] == 0:
        num_zeros += 1
        i += 1
    # f, r = f.quo_rem(R**num_zeros)
    f = f >> (num_zeros-1)
    return f


f1 = load("output/q1/f.sobj")
f2 = load("output/q2/f.sobj")
print(f1.degree(), f2.degree())
f1 = remove_trailing_zeros(f1)
f2 = remove_trailing_zeros(f2)

print(f1.degree(), f2.degree())
# g = f1.gcd(f2)
# print(g.degree())
# print(g)
# print(g.roots(multiplicities=False))

# g, _ = (R**5920775 + 77703463429365363797653215340406821825774*R**5920774).quo_rem(R**5920774)
# print(g.roots(multiplicities=False))

# z0 = ((1337-N)//2) % (p-1)
# z = F(33175117035569038623866551409846851796539)
# # z == pow(m, z0, p)
# m = int(z**(pow(z0, -1, p-1)))
# print(m)

# for z in [136210606624439382131335003299942825798908, 6283739829370994260074505607540699023955]:
#     z = F(z)
#     z0 = ((1337-N)//2) % (q-1)
#     m0 = z.nth_root(z0)
#     c = F(2)**((q-1)//3)
#     for m in [m0, m0*c, m0*c**2]:
#         assert m**z0 == z
#         e, r = [1507812473629110194293471481185667311904951514124028665423740642625702290722644459, 20081874742437640458852890114931041077696527882906352227358367349852439880463037714]
#         if r * z % q == (pow(m, e, q) + pow(m, 3 * e, q)) % q:
#             print("Found!", m)

# # z0 = pow(m, (1337-N)//2, p)
# # e, r = [-160096387411096162260813884403237928950544766809850193629893286493354311685307094, 9755055246011429227505032236338245590751487414579832795245802270841439739807202607]
# # assert r * z0 % p == (pow(m, e, p) + pow(m, 3 * e, p)) % p

# m_p = 79160508705270437219934732832081401695837
# m_q = 129415541925707445779087730082798954094188

# print(hex(crt([m_p, m_q], [p, q])))
