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

n = 112
m = 42

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

def eliminate(problem: ProblemData, index):
    transform = Transform0(index)
    problem = transform.forward(problem)
    return problem, transform

def remove_one_key(problem: ProblemData, index):
    transform = Transform2(index)
    problem = transform.forward(problem)
    return problem, transform


names = ['Miku', 'Rin', 'Len', 'Luka', 'Kaito', 'Meiko', 'Gumi']
pks_uov = [uov.expand_pk(uov.shake256(name.encode(), 43576)) for name in names]
pks = [from_uov(pk) for pk in pks_uov]
t = uov.shake256(b'shrooms', 44)
target = [F.from_integer(i) for i in t]


# pks = [gen(n, 44) for _ in range(7)]
# target = random_vector(F, m)
eqs = [EQ(list(Ms), t) for Ms, t in zip(list(zip(*pks)), target)]

problem_orig = ProblemData(eqs)

# random shuffle
for i in range(256):
    ind = random.randrange(1, 44)
    elm = random.choice(elms)
    eqs[ind] = eqs[ind] + elm * eqs[0]
    eqs[0], eqs[ind] = eqs[ind], eqs[0]
    if i > 128 and eqs[0].v != 0:
        break

problem0 = ProblemData(eqs[:m])

rest_eq0, rest_eq1 = eqs[m:]

def walk(problem, index):
    print(problem.ns, problem.k, problem.m, index)
    n = problem.ns[index]
    m = problem.m
    if n == 0:
        raise ValueError
    if n < m:
        return [remove_one_key(problem, index)]
    elif n > m+1:
        prob1, transform1 = make_one_linear(problem, index)
        prob2, transform2 = eliminate(prob1, index)
        return [(prob1, transform1), (prob2, transform2)]
    elif n == m+1 or n == m:
        prob1, transform1 = make_one_linear(problem, index)
        prob2, transform2 = eliminate(prob1, index)
        prob3, transform3 = remove_one_key(prob2, index)
        return [(prob1, transform1), (prob2, transform2), (prob3, transform3)]


seq = [6,6,6,5,2,5,5,3,2,1,4,3,0,4,4,4,3,3,2,2,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0]

path = []
problem = problem0

for ind in seq:
    path.extend(walk(problem, ind))
    problem = path[-1][0]

print(problem.ns, problem.k, problem.m, ind)
eq0 = problem.eqs[0]
v = eq0.v
M = eq0.Ms[0]

Ts = [identity_matrix(F, 5)]

for problem, transform in reversed(path):
    Ts = transform.compress(Ts)

problem0_compressed = problem0.compress(Ts)
rest_eq0_compressed = rest_eq0.compress(Ts)
rest_eq1_compressed = rest_eq1.compress(Ts)

def try_solve():
    x0 = random_vector(F, 5)
    val  = (x0 * M * x0)
    if val == 0:
        return
    c = F_sqrt(v / val)
    x0 = c * x0

    sol = [x0]

    for problem, transform in reversed(path):
        # assert problem.check(sol), (problem.ns, problem.k, problem.m, len(sol), [len(x) for x in sol], type(transform))
        # sol = transform.backward(sol)
        sol = transform.compress_backward(sol)
    # assert problem0.check(sol)
    # assert problem0_compressed.check(sol)
    if rest_eq0_compressed.evaluate(sol) == 0:
        if rest_eq1_compressed.evaluate(sol) == 0:
            print("Found solution")
            return sol

pbar = tqdm()
def worker_init():
    set_random_seed(os.getpid())

with ProcessPoolExecutor(max_workers=16, initializer=worker_init) as executor: 
    while True:
        tasks = [executor.submit(try_solve) for _ in range(256)]
        for task in tasks:
            sol = task.result()
            if sol is not None:
                break
            pbar.update(1)
        for task in tasks:
            task.cancel()
        if sol is not None:
            break
pbar.close()

real_sol = [T*x for T, x in zip(Ts, sol)]
assert problem0.check(real_sol)
assert rest_eq0.evaluate(real_sol) == 0
assert rest_eq1.evaluate(real_sol) == 0
assert problem_orig.check(real_sol)

sol = to_uov(real_sol)

from pwn import xor

t = xor(*[uov.pubmap(s, pk) for s, pk in zip(sol, pks_uov)])
print(t.hex())
print(uov.shake256(b'shrooms', 44).hex())

