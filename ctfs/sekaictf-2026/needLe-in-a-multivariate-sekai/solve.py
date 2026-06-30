import itertools
from tqdm import tqdm
from hashlib import sha256

from sage.all import *
from sig import Signature

def gcd2(a, b, *args):
    if len(args) == 0:
        return gcd(a, b)
    else:
        return gcd2(gcd(a, b), *args)

def right_kernel_LLL(M):
    k = M.nrows()
    n = M.ncols()
    if k == 0:
        return identity_matrix(n)
    
    M2 = block_matrix(ZZ, [[identity_matrix(n), M.transpose()*2**24]])
    M2 = M2.LLL(algorithm="flatter")
    M2 = M2[:-k]
    assert M2[-1, -1] == 0
    return M2[:, :-k]

def reduce(D, M):
    M2 = D * M * D.transpose()
    T = M2.LLL_gram()
    return T.transpose() * D

def reduce_p(M, p, d):
    assert M.is_positive_definite()
    D = matrix(ZZ, [
        [1, d],
        [0, p]
    ])
    M2 = D * M * D.transpose()
    M2 = (M2 / p).change_ring(ZZ)
    T = M2.LLL_gram()
    return T.transpose() * D

class SubQuadraticForm():
    def __init__(self, M, T, base=1):
        assert T * PK * T.transpose() == M * base
        self.base = base
        self.M = M
        self.T = T
    
    def det(self):
        assert self.base == 1
        return self.M.det()
    
    @property
    def vs(self):
        return self.T.rows()
    
    @staticmethod
    def from_vector(p, v, base=None):
        if base is None:
            M = matrix(ZZ, [[1]])
            T = matrix(ZZ, [v])
            return SubQuadraticForm(M, T, base=p)
        else:
            M = matrix(ZZ, [[p]])
            T = matrix(ZZ, [v])
            return SubQuadraticForm(M, T, base=base)
    
    def merge(self, other):
        if self.base != other.base:
            raise ValueError("base mismatch")
        T_new = block_matrix(ZZ, [[self.T], [other.T]])
        M_new = block_diagonal_matrix([self.M, other.M])
        return SubQuadraticForm(M_new, T_new, base=self.base)
    
    def change_base(self, new_base):
        if self.base == new_base:
            return self
        else:
            M = self.M * self.base / new_base
            M = M.change_ring(ZZ)
            return SubQuadraticForm(M, self.T, base=new_base)
    
    def solve_p(self, p):
        assert self.M.nrows() == 2
        # assume self.M is positive definite
        # find [1, d] * M * [1, d].transpose() = 0 (mod p)
        a = self.M[0, 0]
        b = self.M[0, 1]
        c = self.M[1, 1]
        # solve a + 2bd + cd^2 = 0 (mod p)
        u = mod(b**2 - a * c, p)
        if u.is_square():
            d1 = (-b + u.sqrt()) * inverse_mod(c, p)
            d2 = (-b - u.sqrt()) * inverse_mod(c, p)
            return d1, d2
        else:
            return None
    
    def solve_n(self, n):
        facs = factor(n, algorithm="ecm") # assume factors are distinct primes
        ds = []
        MOD = 1
        for p, _ in facs:
            d1, d2 = self.solve_p(p)
            if MOD == 1:
                ds = [d1, d2]
                MOD = p
            else:
                new_ds = []
                for d in ds:
                    for d_new in [d1, d2]:
                        new_ds.append(crt([d, d_new], [MOD, p]))
                ds = new_ds
                MOD *= p
        return ds
    
    def reduce(self, p):
        ds = self.solve_n(p)
        if ds is None:
            return None
        else:
            ret = []
            for d in ds:
                V = reduce_p(self.M, p, d)
                for v in V.rows():
                    ret.append(((v * self.M * v) // p, v * self.T))
            ret.sort()
            return ret

class OrthoSpace():
    def __init__(self):
        self.vs = []
        self.D = self.get_kernel(PK, self.vs)
    
    def update(self, add_vs):
        self.vs.extend(add_vs)
        self.D = self.get_kernel(PK, self.vs)

    def get_kernel(self, PK, vs):
        n = PK.nrows()
        V = matrix(ZZ, ncols=n, entries=vs)
        T = V * PK
        M0 = right_kernel_LLL(T)
        M0 = reduce(M0, PK)
        return M0

def enum_short_vectors(n):
    # enum a short vector in [-1, 0, 1] ordered by L1 norm
    for w in range(1, n + 1):
        for pos in itertools.combinations(range(n), w):
            for signs in itertools.product([-1, 1], repeat=w):
                if signs[0] == -1:
                    continue # remove duplicates
                v = [0] * n
                for p, s in zip(pos, signs):
                    v[p] = s
                yield v

def enum_two_short_vectors(n):
    # enum a short vector pair in [-1, 0, 1] ordered by L1 norm
    history = []
    for w in range(1, n + 1):
        for pos in itertools.combinations(range(n), w):
            for signs in itertools.product([-1, 1], repeat=w):
                if signs[0] == -1:
                    continue # remove duplicates
                v = [0] * n
                for p, s in zip(pos, signs):
                    v[p] = s
                v2 = tuple(v)
                for v1 in history:
                    yield list(v1), list(v2)
                history.append(v2)

def find_prime(PK, D):
    M = D * PK * D.transpose()
    for v in enum_short_vectors(M.nrows()):
        v = vector(ZZ, v)
        p = v * M * v
        if p.is_pseudoprime():
            yield p, v * D

def iter_pairs(PK, D, coprime=True):
    M = D * PK * D.transpose()
    for v1, v2 in enum_two_short_vectors(M.nrows()):
        C = matrix(ZZ, [v1, v2])
        C2 = C * M * C.transpose()
        if (not coprime) or gcd2(*C2.list()) == 1:
            yield SubQuadraticForm(C2, C * D)

def gen_candidates(S1_reduced, S2_reduced, bound, r):
    candidates = []
    for u in range(2*bound+1):
        if u > bound:
            x = bound
            y = u - bound
        else:
            x = u
            y = bound
        for p1, v1 in S1_reduced:
            for p2, v2 in S2_reduced:
                u = p1 * x**2 + p2 * y**2
                if u.is_pseudoprime() and mod(r, u).is_square():
                    candidates.append((u, v1 * x + v2 * y))
    return candidates

def search_prime(S1_reduced, S2_reduced, r):
    bound = 1
    while True:
        candidates = []
        for b in range(bound, bound + 12):
            candidates.extend(gen_candidates(S1_reduced, S2_reduced, b, r))
        candidates.sort()
        for c in candidates:
            yield c
        bound += 12

sig = Signature.load("pk.sobj")

PK = sig.pk
L = PK.LLL_gram()
PK = L.transpose() * PK * L

O = OrthoSpace()

S0 = next(iter_pairs(PK, O.D))
d = -S0.det()

O.update(S0.vs)

for p1, v in tqdm(find_prime(PK, O.D)):
    if mod(d, p1).is_square():
        ret = S0.reduce(p1)
        assert ret is not None
        if ret[0][0] <= 2**45:
            break

S0 = SubQuadraticForm.from_vector(*S0.reduce(p1)[0], base=p1)
S0 = S0.merge(SubQuadraticForm.from_vector(p1, v))
O.update([v])
r = S0.M[0, 0]

print(S0.M)

for S1 in iter_pairs(PK, O.D):
    d = -S1.det()
    if mod(d, p1).is_square():
        break
O.update(S1.vs)
for S2 in iter_pairs(PK, O.D, coprime=False):
    d = -S2.det()
    if mod(d, p1).is_square():
        break
O.update(S2.vs)

S1_reduced = S1.reduce(p1)
S2_reduced = S2.reduce(p1)
assert S1_reduced is not None and S2_reduced is not None
for p2, v2 in tqdm(search_prime(S1_reduced, S2_reduced, -r)):
    ret = S0.reduce(p2)
    assert ret is not None
    if ret[0][0] <= 2**12:
        break

S1 = SubQuadraticForm.from_vector(p2, v2, base=p1).change_base(p1*p2)
S0 = SubQuadraticForm.from_vector(*S0.reduce(p2)[0], base=p1*p2)
S0 = S0.merge(S1)
print(S0.M, S0.base.bit_length())
r = S0.M[0, 0]

for S2 in iter_pairs(PK, O.D):
    d = -S2.det()
    if mod(d, p2).is_square():
        break
O.update(S2.vs)

# d1, v1 = S1.reduce(p1)[0]
d2, v2 = S2.reduce(p2)[0]

target = int.from_bytes(b"\x01"+sha256(b"STAGE OF SEKAI").digest(), 'big')

print((d2*p1**2*p2).bit_length())

M = O.D * PK * O.D.transpose()
for v0 in enum_short_vectors(M.nrows()):
    v0 = vector(ZZ, v0)
    u = v0 * M * v0
    if (mod(target, p2) / u).is_square():
        r0 = ZZ((mod(target, p2) / u).sqrt())
        assert (target - u*r0**2) % p2 == 0
        vt_base = v0 * r0
        break

for vt in tqdm(enum_short_vectors(M.nrows())):
    vt = vector(ZZ, vt) * p2 + vt_base
    t = target - vt * M * vt
    assert t % p2 == 0
    k = mod(t, p1) / (d2*p2)
    if k.is_square():
        r2 = ZZ(k.sqrt())
        assert (t - d2*p2*r2**2) % (p1*p2) == 0
        for c2 in range(-100, 100):
            r2_cand = r2 + c2*p1
            u = (t - d2*p2*r2_cand**2) // (p1*p2)
            assert u > 0
            if u.is_pseudoprime() and mod(-r, u).is_square():
                ret = S0.reduce(u)
                if ret is not None and ret[0][0] == 1:
                    v0 = ret[0][1]
                    final_v = vt * O.D + v2 * r2_cand + v0
                    assert final_v * PK * final_v == target
                    final_v = L * final_v
                    assert sig.verify(b"STAGE OF SEKAI", final_v.list())
                    print("Found a signature:", final_v)
                    exit()




