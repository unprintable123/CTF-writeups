import os
from real_output import *

os.chdir(os.path.dirname(__file__))

n, k = 36, 8
prime_bit_length = 512
R = Zmod(N)
double_alphas = [R(x) for x in double_alphas]
# alphas = [R(x) for x in alphas]
alphas = None

PR = PolynomialRing(R, [f'x{i}' for i in range(k)])

xlist = [PR.gen(i) for i in range(k)]

def gen_G(double_alphas):
    mat = []
    for i in range(k):
        row = []
        for j in range(k):
            if i % 2 == 0:
                row.append(double_alphas[j]^(i//2))
            else:
                row.append(double_alphas[j]^(i//2) * xlist[j])
        mat.append(row)
    mat = matrix(PR, mat)
    return mat

def mod_double_alphas(poly, double_alphas):
    for i in range(k):
        quo, rem = poly.quo_rem(xlist[i]^2 - double_alphas[i])
        poly = rem
    return poly

def solve_relation(double_alphas, det, alphas=None):

    G_sub = gen_G(double_alphas)
    p = G_sub.det() - det

    def solve_poly(poly, double_alphas, idx):
        for i in range(k):
            if i == idx or i == 0:
                continue
            poly = poly * poly(**{f'x{i}': -xlist[i]})
            poly = mod_double_alphas(poly, double_alphas)
            if alphas is not None:
                assert poly(**{f'x{i}': alphas[i] for i in range(k)}) == 0
        return poly
    
    ul = [double_alphas[0]]

    for j in range(1, k):
        poly2 = solve_poly(p, double_alphas, j)
        u, v = poly2.coefficients()
        if alphas is not None:  
            assert -v/u == alphas[j] * alphas[0]
        ul.append(-v/u)
    
    return ul

ul_list = []

for i in range(5):
    if alphas is not None:
        ul = solve_relation(double_alphas[k*i-i:k*i-i+k], dets[i], alphas[k*i-i:k*i-i+k])
    else:
        ul = solve_relation(double_alphas[k*i-i:k*i-i+k], dets[i])
    ul_list.append(ul)

rel = []

for i in range(5):
    if i == 0:
        rel.extend(ul_list[i])
    else:
        last = R(rel[-1])
        r = last / R(ul_list[i][0])
        rl = [r * x for x in ul_list[i]]
        rel.extend(rl[1:])


r = rel[0]
for i in range(len(rel)):
    rel[i] = rel[i] / r

x = xlist[0]

if alphas is not None:
    for i in range(len(rel)):
        assert rel[i] * alphas[0] == alphas[i], i

def q_pow(p, n, mod):
    if n == 0:
        return 1
    if n == 1:
        return p
    if n % 2 == 0:
        p2 = q_pow(p, n//2, mod)
        p2 = p2 * p2
        p2 = p2.quo_rem(mod)[1]
        return p2
    else:
        p2 = q_pow(p, n//2, mod)
        p2 = p2 * p2
        p2 = p2 * p
        p2 = p2.quo_rem(mod)[1]
        return p2

s = sum(rel) * x
p = q_pow(s, 65537, x**2 - double_alphas[0]) - alpha_sum_rsa
if alphas is not None:
    assert p(x0=alphas[0]) == 0

u, v = p.coefficients()

x0 = -v/u

sol_alphas = [x0 * rel[i] for i in range(36)]
for s, d in zip(sol_alphas, double_alphas):
    assert s^2 == d


