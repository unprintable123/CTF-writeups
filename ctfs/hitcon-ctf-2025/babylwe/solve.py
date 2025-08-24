import os, time, sys
from hashlib import sha256
from random import SystemRandom

from Crypto.Cipher import AES
from sage.all import *
from ast import literal_eval


from g6k import Siever, SieverParams
from g6k.utils.stats import SieveTreeTracer
from fpylll.util import gaussian_heuristic
from six.moves import range
# from g6k.algorithms.workout import workout
from g6k.algorithms.pump import pump
from fpylll import BKZ, GSO, IntegerMatrix, LLL

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter", "-rhf", "1.002"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(ZZ, findall(b"-?\\d+", ret)))

def workout(g6k, tracer, kappa, blocksize, dim4free_min=0,              # Main parameters
            dim4free_dec=1, start_n=40, goal_r0=0.,                     # Loop control
            verbose=False, save_prefix=None, pump_params=None           # Misc
            ):
    """
    :param g6k: The g6k object to work with
    :param tracer: A tracer for g6k
    :param kappa: beginning of the block
    :param blocksize: dimension of the block
    :param dim4free_min: Minimal number of dimension for free ``dimension for free'' [Ducas,
        Eurcrypt 2018] (may stop before reaching that if goal_r0)
    :param dim4free_dec: By how much do we decreaseee dim4free at each iteration
    :param start_n: Dimension of the first pump
    :param goal_r0: an extra hook to always insert at position kappa if this goal length can be met
        by a lift.  Quit when this is reached.
    :param verbose: Print workout steps (with timing and quality) information on the standard
        output.  Enforce verbosity of pump as well.
    :param save_prefix: If not None, save intermediate basis at a file-name with this prefix.
        Allows to resume computation.
    :param pump_params: Parameters to forward to the pump.

    """
    if pump_params is None:
        pump_params = {}

    f_start = max(blocksize - start_n, 0, dim4free_min)
    fs = list(range(dim4free_min, f_start+1, dim4free_dec))[::-1]

    if goal_r0:
        fs += 9999*[dim4free_min]

    gh = gaussian_heuristic([g6k.M.get_r(i, i) for i in range(kappa, kappa+blocksize)])
    runtimestart = time.time()

    if "verbose" not in pump_params:
        pump_params["verbose"] = verbose

    with tracer.context(("workout", "beta:%d f:%d" % (blocksize, dim4free_min))):
        for f in fs:
            flast = f
            timestart = time.time()

            sys.stdout.flush()
            pump(g6k, tracer, kappa, blocksize, f, goal_r0=goal_r0, **pump_params)

            if verbose:
                gh2 = gaussian_heuristic([g6k.M.get_r(i, i) for i in range(kappa+f, kappa+blocksize)])
                quality = (gh * (blocksize - f)) / (gh2 * blocksize)
                print("T:%10.5fs, TT:%10.5fs, q:%10.5f r1/gh:%10.5f" %
                      (time.time() - timestart,
                       time.time() - runtimestart, quality, g6k.M.get_r(1, 1)/gh))
                print(g6k.M.B[1], len(set(literal_eval(str(g6k.M.B[1])))))
                if len(set(literal_eval(str(g6k.M.B[1])))) <= 5:
                    break

            if g6k.M.get_r(kappa, kappa) < goal_r0:
                break

            if save_prefix is not None:
                fn = open("%s_%d_%d.mat" % (save_prefix.rstrip(), g6k.M.d - f, g6k.M.d), "w")
                fn.write(str(g6k.M.B))
                fn.close()

    return flast

n = 64
m = 200
p = 1048583
F = GF(p)

random = SystemRandom()
# errs = random.sample(range(p), 3)
# A = matrix(F, [[random.randrange(0, p - 1) for _ in range(n)] for _ in range(m)])
# s = vector(F, [random.randrange(0, p - 1) for _ in range(n)])
# e = vector(F, [random.choice(errs) for _ in range(m)])
# b = A * s + e

# T = matrix(ZZ, [[errs[1], errs[2]], [0, p], [p, 0]])
# print(T.LLL())
# T = matrix(ZZ, [[errs[0], errs[1], errs[2]], [0, 0, p], [0, p, 0], [0, p, 0], [1, 1, 1]])
# print(T.LLL())

with open("output.txt", "r") as f:
    for line in f:
        exec(line)

A = matrix(F, m, n, A)
b = vector(F, m, b)

A_orig = A
b_orig = b

A = A.augment(b)
A = A.augment(vector(F, [1]*m))
A = A.T
A2 = A.echelon_form()

A3 = zero_matrix(ZZ, m, m)
A3[:n+2] = A2.change_ring(ZZ)
A3[n+2:, n+2:] = identity_matrix(m-n-2) * p

A3 = flatter(A3)

print(A3[1])
X = IntegerMatrix.from_matrix(A3)
M = GSO.Mat(X, float_type="ld", U=IntegerMatrix.identity(m),
            UinvT=IntegerMatrix.identity(m))
g6k = Siever(M, params=SieverParams(threads=12))
tracer = SieveTreeTracer(g6k, root_label=("svp-challenge", n), start_clocks=True)
flast = workout(
    g6k, tracer, 0, m, dim4free_dec=3, verbose=True
)
print(M.B[0])
print(M.B[1])

e0 = vector(F, list(literal_eval(str(M.B[1]))))

if len(set(e0.list())) > 5:
    exit(0)

e0 = vector(F, e0.list())

eqs = []
for _ in range(400):
    i = random.randrange(m)
    j = random.randrange(m)
    if i == j:
        continue
    if e0[i] != e0[j]:
        continue
    eqs.append((A_orig[i] - A_orig[j], b_orig[i] - b_orig[j]))

As, bs = zip(*eqs)
As = matrix(F, list(As))
bs = vector(F, list(bs))

s = As.solve_right(bs)

key = sha256(str(s).encode()).digest()[:24]
aes = AES.new(key[:16], AES.MODE_CTR, nonce=key[-8:])
print(aes.decrypt(b')c\xd7\x11.?j\xe0\x89>\xcf\x15u&\x00el\x86\xae{\xfdv\x97\xe4\xff\x905\x13x\xd5D\x84\xf3\x8e\xb6\'lu\xdd@N>\x91\x1e\xd6\xca"\xdd\xb3?\x92\x1c\x01\xbe'))




