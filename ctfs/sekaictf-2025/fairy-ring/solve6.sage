from tqdm import tqdm
from dataclasses import dataclass
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor
import random, os
from uov import uov_1p_pkc as uov


F = GF(2**8, name='z', modulus=x^8 + x^4 + x^3 + x + 1)
z = F.gen()

R = PolynomialRing(F, 'xbar')
xbar = R.gen()

elms = [F.from_integer(i) for i in range(2**8)]

def gen(n, m):
    U = random_matrix(F, n, n)
    while U.det() == 0:
        U = random_matrix(F, n, n)
    pk = []
    for _ in range(m):
        M = random_matrix(F, n, n)
        M[:m, :m] = 0
        M = U.transpose() * M * U
        pk.append(M)
    return pk

def from_uov_vector(elms):
    m = uov.m
    bs = elms.to_bytes(m, 'big')
    vs = [F.from_integer(i) for i in bs]
    return vs

def from_uov(pk):
    v = uov.v
    m = uov.m
    Ms = [[[0] * n for _ in range(n)] for _ in range(m)]
    m1 = uov.unpack_mtri(pk, v)
    m2 = uov.unpack_mrect(pk[uov.p1_sz:], v, m)
    m3 = uov.unpack_mtri(pk[uov.p1_sz + uov.p2_sz:], m)

    for i in range(v):
        for j in range(i, v):
            vec = from_uov_vector(m1[i][j])
            for k in range(m):
                Ms[k][i][j] = vec[k]

            
    for i in range(v):
        for j in range(m):
            vec = from_uov_vector(m2[i][j])
            for k in range(m):
                Ms[k][i][j + v] = vec[k]
    
    for i in range(m):
        for j in range(i, m):
            vec = from_uov_vector(m3[i][j])
            for k in range(m):
                Ms[k][i + v][j + v] = vec[k]

    Ms = [matrix(F, M) for M in Ms]
    
    return Ms

def to_uov(sol):
    output = []
    for s in sol:
        output.append([x.to_integer() for x in s.list()])
    output = [bytearray(x) for x in output]
    return output

def F_sqrt(x):
    # return x**128
    return x.square_root()

quad_sols = {}
for u in elms:
    for t in elms:
        quad_sols[(u, t)] = []
    for x in elms:
        t = u * x + x**2
        quad_sols[(u, t)].append(x)

def F_quad_solve(u, t):
    # solve x^2 + u * x + t = 0
    return quad_sols[(u, t)]

class EQ:
    def __init__(self, Ms: list, v):
        self.Ms = Ms
        self.v = v
    
    def evaluate(self, sigs):
        result = 0
        for M, sig in zip(self.Ms, sigs):
            result += sig * M * sig
        result += self.v
        return result
    
    def evaluate_M(self, sigs):
        result = 0
        for M, sig in zip(self.Ms, sigs):
            result += sig * M * sig
        return result
    
    def compress(self, Ts):
        new_Ms = []
        for M, T in zip(self.Ms, Ts):
            new_Ms.append(T.transpose() * M * T)
        return EQ(new_Ms, self.v)

    @property
    def ns(self):
        return [M.nrows() for M in self.Ms]
    
    def __mul__(self, other):
        other = F(other)
        new_Ms = [other * M for M in self.Ms]
        new_v = other * self.v
        return EQ(new_Ms, new_v)
    
    def __add__(self, other):
        assert isinstance(other, EQ)
        assert len(self.Ms) == len(other.Ms)
        new_Ms = [M + other.Ms[i] for i, M in enumerate(self.Ms)]
        new_v = self.v + other.v
        return EQ(new_Ms, new_v)
    
    def  __rmul__(self, other):
        other = F(other)
        return self.__mul__(other)

class ProblemData:
    def __init__(self, eqs: list[EQ]):
        self.eqs = eqs
        self.ns = eqs[0].ns
        self.k = len(self.ns)
        self.m = len(eqs)
        for i in range(1, self.m):
            assert eqs[i].ns == self.ns

    def check(self, sigs):
        vs = [eq.evaluate(sigs) for eq in self.eqs]
        return all(v == 0 for v in vs)

    def get_M(self, i, index):
        return self.eqs[i].Ms[index]

    def get_key(self, index):
        Ms = [self.get_M(i, index) for i in range(self.m)]
        return Ms
    
    def compress(self, Ts):
        new_eqs = [eq.compress(Ts) for eq in self.eqs]
        return ProblemData(new_eqs)

class Transform:
    def __init__(self):
        pass

    def forward(self, problem: ProblemData):
        raise NotImplementedError
    
    def compress(self, Ts):
        raise NotImplementedError

    def backward(self, x):
        raise NotImplementedError
    
    def compress_backward(self, x_compressed):
        raise NotImplementedError
    
    def batch_compress_backward(self, x_compressed_list):
        raise NotImplementedError

class Transform0(Transform):
    def __init__(self, index):
        self.index = index
        self.eq = None

    def forward(self, problem: ProblemData):
        Ms = problem.get_key(self.index)
        Ms = [M + M.transpose() for M in Ms]
        assert all(M[0].is_zero() for M in Ms)
        m = len(Ms)
        eqs = problem.eqs[:]
        for i0 in range(m):
            if Ms[i0][0, 0] != 0:
                break
        eqs[0], eqs[i0] = eqs[i0], eqs[0]
        coeffs = [eqs[i].Ms[self.index][0, 0] for i in range(problem.m)]
        eqs[0] = eqs[0] * coeffs[0].inverse()
        for i in range(1, problem.m):
            eqs[i] = eqs[i] + (-coeffs[i]) * eqs[0]
        assert eqs[0].Ms[self.index][0, 0] == 1
        for i in range(problem.m):
            eqs[i].Ms[self.index] = eqs[i].Ms[self.index][1:, 1:]
        self.eq = eqs.pop(0)
        return ProblemData(eqs)
    
    def compress(self, Ts):
        self.compressed_eq = self.eq.compress(Ts)
        new_Ts = Ts[:]
        new_Ts[self.index] = block_matrix(F, [[identity_matrix(1), 0], [0, Ts[self.index]]])
        return new_Ts
    
    def backward(self, x):
        u = self.eq.evaluate(x)
        x0 = F_sqrt(u)
        v0 = x[self.index]
        v1 = vector(F, [x0] + v0.list())
        x_new = x[:]
        x_new[self.index] = v1
        return x_new
    
    def compress_backward(self, x_compressed):
        u = self.compressed_eq.evaluate(x_compressed)
        x0 = F_sqrt(u)
        v0 = x_compressed[self.index]
        v1 = vector(F, [x0] + v0.list())
        x_new = x_compressed[:]
        x_new[self.index] = v1
        return x_new

    def batch_compress_backward(self, x_compressed_list):
        return [self.compress_backward(x) for x in x_compressed_list]


class Transform1(Transform):
    def __init__(self, index, T):
        self.index = index
        self.T = T
    
    def forward(self, problem):
        return ProblemData([self.apply_T(eq) for eq in problem.eqs])

    def apply_T(self, eq: EQ):
        Ms = eq.Ms[:]
        Ms[self.index] = self.T.transpose() * Ms[self.index] * self.T
        return EQ(Ms, eq.v)
    
    def compress(self, Ts):
        new_Ts = Ts[:]
        new_Ts[self.index] = self.T * Ts[self.index]
        return new_Ts
    
    def backward(self, x):
        x0 = x[self.index]
        x_new = x[:]
        x_new[self.index] = self.T * x0
        return x_new
    
    def compress_backward(self, x_compressed):
        return x_compressed
    
    def batch_compress_backward(self, x_compressed_list):
        return x_compressed_list[:]

class Transform2(Transform):
    def __init__(self, index):
        self.index = index
        self.eq = None
        self.pad = 0
    
    def forward(self, problem: ProblemData):
        Ms = problem.get_key(self.index)
        m = len(Ms)
        self.pad = Ms[0].nrows() - 1
        eqs = problem.eqs[:]
        for i0 in range(m):
            if Ms[i0][0, 0] != 0:
                break
        eqs[0], eqs[i0] = eqs[i0], eqs[0]
        coeffs = [eqs[i].Ms[self.index][0, 0] for i in range(problem.m)]
        eqs[0] = eqs[0] * coeffs[0].inverse()
        for i in range(1, problem.m):
            eqs[i] = eqs[i] + (-coeffs[i]) * eqs[0]
        assert eqs[0].Ms[self.index][0, 0] == 1
        new_eqs = []
        for i in range(problem.m):
            eq = eqs[i]
            Ms = eq.Ms[:]
            Ms.pop(self.index)
            new_eqs.append(EQ(Ms, eq.v))
        self.eq = new_eqs.pop(0)
        return ProblemData(new_eqs)

    def compress(self, Ts):
        self.compressed_eq = self.eq.compress(Ts)
        new_T = matrix(F, [[1]] + [[0] for _ in range(self.pad)])
        new_Ts = Ts[:self.index] + [new_T] + Ts[self.index:]
        return new_Ts
    
    def backward(self, x):
        u = self.eq.evaluate(x)
        x0 = F_sqrt(u)
        v1 = vector(F, [x0] + [0] * self.pad)
        x_new = x[:self.index] + [v1] + x[self.index:]
        return x_new
    
    def compress_backward(self, x_compressed):
        u = self.compressed_eq.evaluate(x_compressed)
        x0 = F_sqrt(u)
        v1 = vector(F, [x0])
        x_new = x_compressed[:self.index] + [v1] + x_compressed[self.index:]
        return x_new
    
    def batch_compress_backward(self, x_compressed_list):
        return [self.compress_backward(x) for x in x_compressed_list]

class Transform3(Transform):
    def __init__(self, index):
        self.index = index
        self.eq = None
        self.u = None

    def forward(self, problem: ProblemData):
        Ms = problem.get_key(self.index)
        m = len(Ms)
        for i0 in range(m):
            if Ms[i0][0, 0] != 0:
                break
        eqs = problem.eqs[:]
        eqs[0], eqs[i0] = eqs[i0], eqs[0]
        coeffs = [eqs[i].Ms[self.index][0, 0] for i in range(problem.m)]
        eqs[0] = eqs[0] * coeffs[0].inverse()
        for i in range(1, problem.m):
            eqs[i] = eqs[i] + (-coeffs[i]) * eqs[0]
        M_is = [eqs[i].Ms[self.index] for i in range(problem.m)]
        for i in range(1, m):
            assert M_is[i][0, 0] == 0
            assert (M_is[i] + M_is[i].transpose())[0].is_zero()
        self.u = (M_is[0]+M_is[0].transpose())[0][1:]
        for i in range(problem.m):
            eqs[i].Ms[self.index] = eqs[i].Ms[self.index][1:, 1:]
        self.eq = eqs.pop(0)
        return ProblemData(eqs)
    
    def compress(self, Ts):
        self.compressed_eq = self.eq.compress(Ts)
        self.compressed_u = self.u * Ts[self.index]
        new_Ts = Ts[:]
        new_Ts[self.index] = block_matrix(F, [[identity_matrix(1), 0], [0, Ts[self.index]]])
        return new_Ts

    def compress_backward_2(self, x_compressed):
        v0 = self.compressed_eq.evaluate(x_compressed)
        u0 = self.compressed_u * x_compressed[self.index]
        x0_sols = F_quad_solve(u0, v0)
        sols = []
        for x0 in x0_sols:
            v1 = vector(F, [x0] + x_compressed[self.index].list())
            x_new = x_compressed[:]
            x_new[self.index] = v1
            sols.append(x_new)
        return sols
    
    def batch_compress_backward(self, x_compressed_list):
        ret = []
        for x in x_compressed_list:
            ret.extend(self.compress_backward_2(x))
        return ret

def solve_T_even(Ms):
    Ms2 = [M + M.transpose() for M in Ms]
    n = Ms2[0].nrows()
    k = len(Ms2)
    if k >= n+1:
        raise ValueError
    for e in elms:
        M0 = Ms2[0] + e * Ms2[1]
        if M0.det() != 0:
            break
    M1 = Ms2[1] * M0.inverse()
    M2 = Ms2[2] * M0.inverse()
    M3 = Ms2[3] * M0.inverse()
    for e1 in elms:
        for e2 in elms:
            MM = M1 + e1 * M2 + e2 * M3
            r = MM.charpoly().roots()
            if len(r) == 0:
                continue
            r0 = r[0][0]
            b = (MM-r0*identity_matrix(F, n)).left_kernel().basis()[0]
            if b[0] == 0:
                continue
            b = b / b[0]
            T = identity_matrix(F, n)
            T[0] = b
            Ms3 = [T*M*T.transpose() for M in Ms]
            C = zero_matrix(F, k, n-1)
            for i in range(k):
                M_tmp = Ms3[i] + Ms3[i].transpose()
                C[i] = M_tmp[0][1:]
            if C.rank() >= n-1:
                continue
            bs = C.right_kernel().matrix()
            T2 = block_matrix(F, [[identity_matrix(1),0], [0,bs]])
            # Ms4 = [T2*M*T2.transpose() for M in Ms3]
            return (T2*T).transpose()

def solve_T_small(Ms):
    n = Ms[0].nrows()
    k = len(Ms)
    if k >= n+1:
        raise ValueError

    C = zero_matrix(F, k, n-1)
    for i in range(k):
        M_tmp = Ms[i] + Ms[i].transpose()
        C[i] = M_tmp[0][1:]
    bs = C.right_kernel().matrix()
    T2 = block_matrix(F, [[identity_matrix(1),0], [0,bs]])
    # Ms4 = [T2*M*T2.transpose() for M in Ms3]
    return T2.transpose()

def solve_T_odd(Ms):
    Ms2 = [M + M.transpose() for M in Ms]
    n = Ms2[0].nrows()
    k = len(Ms2)
    if k >= n+1:
        raise ValueError
    M0 = Ms2[0]
    M1 = Ms2[1]
    M2 = Ms2[2]
    for e1 in elms:
        for e2 in elms:
            MM = M0 + e1 * M1 + e2 * M2
            b = MM.left_kernel().basis()[0]
            if b[0] == 0:
                continue
            b = b / b[0]
            T = identity_matrix(F, n)
            T[0] = b
            Ms3 = [T*M*T.transpose() for M in Ms]
            C = zero_matrix(F, k, n-1)
            for i in range(k):
                M_tmp = Ms3[i] + Ms3[i].transpose()
                C[i] = M_tmp[0][1:]
            if C.rank() >= n-1:
                continue
            bs = C.right_kernel().matrix()
            T2 = block_matrix(F, [[identity_matrix(1),0], [0,bs]])
            # Ms4 = [T2*M*T2.transpose() for M in Ms3]
            return (T2*T).transpose()

def solve_T_even_semi_linear(Ms):
    Ms2 = [M + M.transpose() for M in Ms]
    n = Ms2[0].nrows()
    k = len(Ms2)
    if k >= n+1:
        raise ValueError
    for e0 in elms:
        M0 = Ms2[0] + e0 * Ms2[1]
        if M0.det() != 0:
            break
    M1 = Ms2[1] * M0.inverse()
    M2 = Ms2[2] * M0.inverse()
    M3 = Ms2[3] * M0.inverse()
    for e1 in elms:
        for e2 in elms:
            MM = M1 + e1 * M2 + e2 * M3
            r = MM.charpoly().roots()
            if len(r) == 0:
                continue
            r0 = r[0][0]
            # b = (MM-r0*identity_matrix(F, n)).left_kernel().basis()[0]
            U0 = r0*(Ms[0]+e0*Ms[1])+Ms[1]+e1 * Ms[2]+e2 * Ms[3]
            for b in (MM-r0*identity_matrix(F, n)).left_kernel().basis():
                if b[0] == 0:
                    continue
                if b*U0*b != 0:
                    continue
                b = b / b[0]
                T = identity_matrix(F, n)
                T[0] = b

                Ms3 = [T*M*T.transpose() for M in Ms]
                
                Ms3_copy = Ms3[:]
                for i0 in range(k):
                    if Ms3_copy[i0][0, 0] != 0:
                        break
                Ms3_copy[0], Ms3_copy[i0] = Ms3_copy[i0], Ms3_copy[0]
                Ms3_copy[0] = Ms3_copy[0] * Ms3_copy[0][0, 0].inverse()
                for i in range(1, k):
                    if Ms3_copy[i][0, 0] == 0:
                        continue
                    Ms3_copy[i] = Ms3_copy[i] - Ms3_copy[i][0, 0] * Ms3_copy[0]
                
                C = zero_matrix(F, k-1, n-1)
                for i in range(1, k):
                    M_tmp = Ms3_copy[i] + Ms3_copy[i].transpose()
                    C[i-1] = M_tmp[0][1:]
                if C.rank() >= n-1:
                    continue
                bs = C.right_kernel().matrix()
                T2 = block_matrix(F, [[identity_matrix(1),0], [0,bs]])
                # Ms4 = [T2*M*T2.transpose() for M in Ms3]
                return (T2*T).transpose()

def solve_T_odd_semi_linear(Ms):
    Ms2 = [M + M.transpose() for M in Ms]
    n = Ms2[0].nrows()
    k = len(Ms2)
    if k >= n:
        raise ValueError
    M0 = Ms2[0]
    M1 = Ms2[1]
    M2 = Ms2[2]
    for e1 in elms:
        for e2 in elms:
            MM = M0 + e1 * M1 + e2 * M2
            b = MM.left_kernel().basis()[0]
            if b[0] == 0:
                continue
            b = b / b[0]
            T = identity_matrix(F, n)
            T[0] = b

            U0 = Ms[0] + e1 * Ms[1] + e2 * Ms[2]
            if b*U0*b != 0:
                continue

            Ms3 = [T*M*T.transpose() for M in Ms]
            
            Ms3_copy = Ms3[:]
            for i0 in range(k):
                if Ms3_copy[i0][0, 0] != 0:
                    break
            Ms3_copy[0], Ms3_copy[i0] = Ms3_copy[i0], Ms3_copy[0]
            Ms3_copy[0] = Ms3_copy[0] * Ms3_copy[0][0, 0].inverse()
            for i in range(1, k):
                if Ms3_copy[i][0, 0] == 0:
                    continue
                Ms3_copy[i] = Ms3_copy[i] - Ms3_copy[i][0, 0] * Ms3_copy[0]
            
            C = zero_matrix(F, k-1, n-1)
            for i in range(1, k):
                M_tmp = Ms3_copy[i] + Ms3_copy[i].transpose()
                C[i-1] = M_tmp[0][1:]
            if C.rank() >= n-1:
                continue
            bs = C.right_kernel().matrix()
            T2 = block_matrix(F, [[identity_matrix(1),0], [0,bs]])
            return (T2*T).transpose()

def solve_T_small_semi_linear(Ms):
    Ms2 = [M + M.transpose() for M in Ms]
    n = Ms2[0].nrows()
    k = len(Ms2)

    Ms3_copy = Ms[:]
    for i0 in range(k):
        if Ms3_copy[i0][0, 0] != 0:
            break
    Ms3_copy[0], Ms3_copy[i0] = Ms3_copy[i0], Ms3_copy[0]
    Ms3_copy[0] = Ms3_copy[0] * Ms3_copy[0][0, 0].inverse()
    for i in range(1, k):
        if Ms3_copy[i][0, 0] == 0:
            continue
        Ms3_copy[i] = Ms3_copy[i] - Ms3_copy[i][0, 0] * Ms3_copy[0]
    
    C = zero_matrix(F, k-1, n-1)
    for i in range(1, k):
        M_tmp = Ms3_copy[i] + Ms3_copy[i].transpose()
        C[i-1] = M_tmp[0][1:]
    bs = C.right_kernel().matrix()
    T2 = block_matrix(F, [[identity_matrix(1),0], [0,bs]])
    return T2.transpose()
    

def make_one_linear(problem: ProblemData, index):
    ns = problem.ns
    Ms = problem.get_key(index)
    if problem.m <= 2:
        T = solve_T_small(Ms)
    elif ns[index] % 2 == 0:
        T = solve_T_even(Ms)
    else:
        T = solve_T_odd(Ms)
    if T is None:
        raise ValueError
    transform = Transform1(index, T)
    problem = transform.forward(problem)
    return problem, transform

def make_one_semi_linear(problem: ProblemData, index):
    ns = problem.ns
    Ms = problem.get_key(index)
    if problem.m <= 3:
        T = solve_T_small_semi_linear(Ms)
    elif ns[index] % 2 == 0:
        T = solve_T_even_semi_linear(Ms)
    else:
        T = solve_T_odd_semi_linear(Ms)
    if T is None:
        raise ValueError
    transform = Transform1(index, T)
    problem = transform.forward(problem)
    return problem, transform

def eliminate(problem: ProblemData, index):
    transform = Transform0(index)
    problem = transform.forward(problem)
    return problem, transform

def eliminate_semi_linear(problem: ProblemData, index):
    transform = Transform3(index)
    problem = transform.forward(problem)
    return problem, transform

def remove_one_key(problem: ProblemData, index):
    transform = Transform2(index)
    problem = transform.forward(problem)
    return problem, transform


n = 112
m = 40

# names = ['Miku', 'Ichika', 'Minori', 'Kohane', 'Tsukasa', 'Kanade']
# pks_uov = [uov.expand_pk(uov.shake256(name.encode(), 43576)) for name in names]

pks_uov = []
for pub in os.listdir('fairy-ring/keys'):
    print(pub)
    with open(f'fairy-ring/keys/{pub}', 'rb') as f:
        pk = f.read()
    pks_uov.append(uov.expand_pk(pk))

pks = [from_uov(pk) for pk in pks_uov]
# message = b'SEKAI'
message = b'shrooms'
t = uov.shake256(message, 44)
target = [F.from_integer(i) for i in t]


# pks = [gen(n, 44) for _ in range(7)]
# target = random_vector(F, m)
eqs = [EQ(list(Ms), t) for Ms, t in zip(list(zip(*pks)), target)]
# eqs = eqs[:43]

problem_orig = ProblemData(eqs[:])

# random shuffle
for i in range(256):
    ind = random.randrange(1, len(eqs))
    elm = random.choice(elms)
    eqs[ind] = eqs[ind] + elm * eqs[0]
    eqs[0], eqs[ind] = eqs[ind], eqs[0]
    if i > 128 and eqs[0].v != 0:
        break

last_eq = eqs.pop(0)
last_eq = last_eq * last_eq.v.inverse()
for i in range(len(eqs)):
    eqs[i] = eqs[i] + (-eqs[i].v) * last_eq

problem0 = ProblemData(eqs[:m])

rest_eqs = eqs[m:]

def walk(problem, index):
    print(problem.ns, problem.k, problem.m, index)
    n = problem.ns[index]
    m = problem.m
    if n == 0:
        raise ValueError
    if n < m:
        return [remove_one_key(problem, index)]
    elif n > m+1:
        if index != 2 and index != 4:
            prob1, transform1 = make_one_semi_linear(problem, index)
            prob2, transform2 = eliminate_semi_linear(prob1, index)
        else:
            prob1, transform1 = make_one_linear(problem, index)
            prob2, transform2 = eliminate(prob1, index)
        return [(prob1, transform1), (prob2, transform2)]
    elif n == m+1 or n == m:
        prob1, transform1 = make_one_linear(problem, index)
        prob2, transform2 = eliminate(prob1, index)
        prob3, transform3 = remove_one_key(prob2, index)
        return [(prob1, transform1), (prob2, transform2), (prob3, transform3)]


# seq = [6,6,6,5,2,5,5,3,2,1,4,3,0,4,4,4,3,3,2,2,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0]
seq = [4,5,5,5,4,4,4,2,3,2,3,3,3,2,2,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

path = []
problem = problem0

for ind in seq:
    path.extend(walk(problem, ind))
    problem = path[-1][0]

print(problem.ns, problem.k, problem.m, ind)
eq0 = problem.eqs[0]
assert eq0.v == 0
M = eq0.Ms[0]
M = M / M[0][0]
M0 = M[1:, 1:]
u0 = (M+M.transpose())[0][1:]

Ts = [identity_matrix(F, 5)]

for problem, transform in reversed(path):
    Ts = transform.compress(Ts)

problem0_compressed = problem0.compress(Ts)
rest_eqs_compressed = [eq.compress(Ts) for eq in rest_eqs]
last_eq_compressed = last_eq.compress(Ts)

def try_solve():
    x0 = random_vector(F, 4)
    val = (x0 * M0 * x0)
    u = u0 * x0
    xsols = F_quad_solve(u, val)
    if len(xsols) == 0:
        return 0, None

    sols = []
    for i in range(len(xsols)):
        x = vector(F, [xsols[i]] + x0.list())
        sols.append([x])

    for problem, transform in reversed(path):
        if len(sols) == 0:
            return 0, None
        # assert problem.check(sol), (problem.ns, problem.k, problem.m, len(sol), [len(x) for x in sol], type(transform))
        # sol = transform.backward(sol)
        
        sols = transform.batch_compress_backward(sols)
    # assert problem0.check(sol)
    # assert problem0_compressed.check(sols[0])
    for sol in sols:
        find = True
        for i, eq in enumerate(rest_eqs_compressed):
            if eq.evaluate(sol) != 0:
                if i == len(rest_eqs_compressed) - 1:
                    print("Checking last eq", eq.evaluate(sol))
                find = False
                break
        if not find:
            continue
        r = last_eq_compressed.evaluate_M(sol)
        if r == 0:
            print("Sad...")
            continue
        v = last_eq_compressed.v
        scale = F_sqrt(v/r)
        sol = [scale * x for x in sol]
        print("Found solution")
        return len(sols), sol
    return len(sols), None

pbar = tqdm()
def worker_init():
    seed = os.getpid() + random.randint(0, 2**24)
    set_random_seed(seed)

with ProcessPoolExecutor(max_workers=8, initializer=worker_init) as executor:
    tasks = []
    for i in range(512):
        tasks.append(executor.submit(try_solve))
    
    while True:
        task = tasks.pop(0)
        cnt, sol = task.result()
        if sol is not None:
            break
        pbar.update(cnt)
        tasks.append(executor.submit(try_solve))
    for task in tasks:
        task.cancel()
pbar.close()

real_sol = [T*x for T, x in zip(Ts, sol)]
assert problem0.check(real_sol)
assert all(eq.evaluate(real_sol) == 0 for eq in rest_eqs)
assert problem_orig.check(real_sol)

sol = to_uov(real_sol)

print("".join(s.hex() for s in sol))

from pwn import xor

print(len(pks_uov))
t = xor(*[uov.pubmap(s, pk) for s, pk in zip(sol, pks_uov)])
print(t.hex())
print(uov.shake256(message, 44).hex())

