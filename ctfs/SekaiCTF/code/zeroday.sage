from re import fullmatch
import os
import itertools

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

flag = b"SEKAI{" + b"a" * 32 + b"}"

assert fullmatch(rb'SEKAI{\w{32}}', flag)

# print([pow(int.from_bytes(flag[6:-1], 'big') + i, -1, 2**255-19) >> 170 for i in range(1+3+3+7)])
[29431621415867921698671444, 12257315102018176664717361, 6905311467813097279935853, 13222913226749606936127836, 25445478808277291772285314, 9467767007308649046406595, 33796240042739223741879633, 520979008712937962579001, 31472015353079479796110447, 38623718328689304853037278, 17149222936996610613276307, 21988007084256753502814588, 11696872772917077079195865, 6767350497471479755850094]

q = 2**255-19
oc = int.from_bytes(os.urandom(32), 'big')

# oracles = [pow(oc + i, -1, q) for i in range(20)]

def build_sbg(k, d, i_list, x_list):
    assert k>= 2*d-2
    assert len(i_list) == k

    def build_row(xi, i):
        return [xi*(pow(i, u)) for u in range(d)] + [pow(i, u) for u in range(k-d)]

    # return matrix([build_row(x, i) for x, i in zip(x_list, i_list)])
    return matrix([build_row(x_list[i], i) for i in i_list])

li = [13,9,3,4,5,6,7,8,0,17]
# assert (build_sbg(10, 6, li, oracles).det()-build_sbg(10, 5, li, oracles).det())%(q**5) == 0

def F(x,y,z,w):
    li = [x,y,z,w]

    plist = []
    real_plist = []
    for a, b in [(0,1), (0,2), (0,3), (1,2), (1,3), (2,3)]:
        u1, u2 = set([0,1,2,3]).difference([a,b])
        poly1 = ((x**2*alist[a]*alist[b]+x*(li[a]*alist[a]+li[b]*alist[b]-2)))
        plist.append(poly1*alist[u1])
        plist.append(poly1*alist[u2])
        poly2 = ((x+li[a])*alist[a]-1)*((x+li[b])*alist[b]-1)
        real_plist.append(poly2*alist[u1])
        real_plist.append(poly2*alist[u2])

    ms = sum(p0*randint(10, 2**32) for p0 in plist).monomials()
    def to_coef(poly):
        coefs = poly.coefficients()
        monos = poly.monomials()
        t = [0] * len(ms)
        for i, m in enumerate(ms):
            if m in monos:
                t[i] = coefs[monos.index(m)]
        return t

    B = matrix([to_coef(poly) for poly in plist])
    v = B.left_kernel().basis()[0]
    poly = 0
    for i in range(len(v)):
        poly += v[i]*real_plist[i]
    return poly

R.<x,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,i,j,k,l> = PolynomialRing(ZZ)
alist = [a0,a1,a2,a3,a4,a5,a6,a7,a8,a9]
# highbits = [n>>170 for n in oracles]
highbits = [29431621415867921698671444, 12257315102018176664717361, 6905311467813097279935853, 13222913226749606936127836, 25445478808277291772285314, 9467767007308649046406595, 33796240042739223741879633, 520979008712937962579001, 31472015353079479796110447, 38623718328689304853037278, 17149222936996610613276307, 21988007084256753502814588, 11696872772917077079195865, 6767350497471479755850094]
true_vlist = [a+n*(2**170) for a,n in zip(alist, highbits)]
# redacted_vlist = {f"a{i}": n & ((2**170)-1) for i, n in enumerate(oracles[:10])}
# print(redacted_vlist)

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
for d in range(7):
    bs = create_basis(10, d)
    all_basis.extend(bs)
monomials = [c[0] for c in all_basis]
# basis_true_value = vector(ZZ, [(c[1])(**redacted_vlist) for c in all_basis])
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
print(len(decomposed_eqs))

# assert all(eq*basis_true_value%(q**5) == 0 for eq in decomposed_eqs)


M = matrix(decomposed_eqs)

scale_d = {
    0: 1,
    1: 2**170,
    2: 2**341,
    3: 2**512,
    4: 2**688,
    5: 2**870,
    6: 2**1054
}
# print([b.bit_length() for b in basis_true_value])
# scale = [2**b.bit_length() for b in basis_true_value]
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
# print(basis_true_value[:10])

bs = M.right_kernel().basis()

print(bs[0][:10])
print(bs[1][:10])

a00 = bs[0][1]

x00 = pow(a00 + highbits[0]*(2**170), -1, q)
print(x00)

# h = M*vec_basis
# kkk = 232
# h = list(h[:kkk])
# for i in range(kkk):
#     assert (h[i])(**redacted_vlist) == 0, f"{i} {h[i](**redacted_vlist)//(q**5)}"
# assert all(M[i]*basis_true_value == 0 for i in range(10))

print([pow(x00 + i, -1, 2**255-19) >> 170 for i in range(1+3+3+7)])


