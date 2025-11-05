from sage.all import *
import cuso
from pwn import *
from ast import literal_eval

context.log_level = 'debug'

io = process(['sage', 'server.py'])



n, p_high = map(int, io.recvline().decode().strip().split())

R = PolynomialRing(Zmod(n), 'x')
x = R.gen()

f = (p_high << 233) + x
x0 = f.small_roots(X=2**233, beta=0.49, epsilon=0.03)[0]

p = int((p_high << 233) + x0)
assert n % p == 0
q = n // p
io.sendline(str(p).encode())

io.recvuntil(b"as:")

n, p0, p1, p2 = literal_eval(io.recvline().decode().strip())

x0, x1, x2 = var('x0 x1 x2')
relations = [
    p0 - x0,
    p1 - x1,
    p2 - x2,
]
bounds = {
    x0: (0, 2**312),
    x1: (0, 2**312),
    x2: (0, 2**312),
}
roots = cuso.find_small_roots(
    relations,
    bounds,
    modulus="p",
    modulus_multiple = n,
    modulus_lower_bound = 2**255,
    use_graph_optimization =False,
)
print(roots)




# prob 3

data = []

for _ in range(5):
    p, x_i, a_i = map(int, io.recvline().decode().strip().split())
    data.append((x_i,a_i))

xs, lowbits = zip(*data)
xs = list(xs)
lowbits = list(lowbits)

from re import fullmatch, findall
import os
import itertools

def flatter(M):
    from subprocess import check_output
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


def build_sbg(k, d, i_list, x_list):
    assert k>= 2*d-2
    assert len(i_list) == k

    def build_row(xi, i):
        return [xi*(pow(i, u)) for u in range(d)] + [pow(i, u) for u in range(k-d)]

    # return matrix([build_row(x, i) for x, i in zip(x_list, i_list)])
    return matrix([build_row(x_list[i], i) for i in i_list])

R = PolynomialRing(ZZ, names=('x','a0','a1','a2','a3','a4'))
x,a0,a1,a2,a3,a4 = R.gens()
alist = [a0,a1,a2,a3,a4]
true_vlist = [a*(2**400)+n for a,n in zip(alist, lowbits)]

def create_basis(n,d):
    if d==0:
        return [(set(), R(1))]
    if d==1:
        return [(set([i]), a) for i, a in enumerate(alist)]
    S = list(range(0, n-d+2))
    T = list(range(n-d+2, n))
    # subset of S size d
    basis = []
    for subset in itertools.combinations(S, d):
        A = build_sbg(2*d-2, d, list(subset)+T, alist)
        poly = A.det()
        basis.append((set(subset), poly))
    return basis

all_basis = []
for d in range(6):
    bs = create_basis(5, d)
    all_basis.extend(bs)
monomials = [c[0] for c in all_basis]
vec_basis = vector(R, [c[1] for c in all_basis])

assert len(all_basis) == 232

def create_eqs(d):
    assert d >= 2
    n = 10
    S = list(range(0, n-d+2))
    T = list(range(n-d+2, n))
    eqs = []
    for subset in itertools.combinations(S, d):
        poly = build_sbg(2*d-2, d, list(subset)+T, true_vlist).det() - (-1)**d * build_sbg(2*d-2, d-1, list(subset)+T, true_vlist).det()
        # assert poly(**redacted_vlist)%(q**(d-1)) == 0
        eqs.append(poly*(q**(6-d)))
    return eqs

all_eqs = []
for d in range(2, 7):
    all_eqs += create_eqs(d)

def decompose_sbg(poly):
    if poly == 0:
        return [0] * len(monomials)

    def find_ids():
        deg = poly.degree()
        for mono in poly.monomials():
            if mono.degree() == deg:
                vs = mono.variables()
                ids = [alist.index(v) for v in vs]
                assert len(ids) == deg
                if set(ids) in monomials:
                    return set(ids)

    ids = find_ids()
    assert ids is not None, poly.monomials()
    for s, p in all_basis:
        if s == ids:
            di, rem = poly.quo_rem(p)
            decomposed = decompose_sbg(rem)
            assert di.monomials() == [1]
            decomposed[monomials.index(ids)] += di
            return decomposed

decomposed_eqs = [vector(ZZ, decompose_sbg(eq)) for eq in all_eqs]
M = matrix(decomposed_eqs)
print(len(decomposed_eqs))

# assert all(eq*basis_true_value%(q**5) == 0 for eq in decomposed_eqs)

scale_d = {
    0: 1,
    1: 2**112,
    2: 2**224,
    3: 2**336,
    4: 2**450,
    5: 2**562,
}
# print([b.bit_length() for b in basis_true_value])
scale = [scale_d[len(m)] for m in monomials]
assert len(scale) == 232

M = block_matrix([[M], [(q**5)*identity_matrix(232)[:11]]])

print(M.nrows(), M.ncols())

for i, s in enumerate(scale):
    M.rescale_col(i, s)

M = flatter(M)
M = M.change_ring(QQ)
for i, s in enumerate(scale):
    M.rescale_col(i, 1/s)
M = M.change_ring(ZZ)

M = M[:230]
# assert M * basis_true_value == vector(ZZ, [0]*230)

bs = M.right_kernel().basis()

print(bs[0][:10])
print(bs[1][:10])

a00 = bs[0][1]
x00 = pow(a00 + highbits[0]*(2**170), -1, q)

print(x00)
print([pow(x00 + i, -1, 2**255-19) >> 170 for i in range(1+3+3+7)])