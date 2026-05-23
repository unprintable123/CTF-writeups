from sage.all import *
from subprocess import Popen, PIPE
from tqdm import tqdm, trange
import sys
import json
import time
load("composed_prod.pyx")

p = 110878580464934402421519766750253673622313
q = 142494346453810376391409508907483524822863
N = p * q

with open("candidates_p.json", "r") as f:
    candidates_p = json.load(f)
score = abs(candidates_p[2][0])
v, ers = candidates_p[2][1]
print("Best candidate for p:", v, "with score", score)

num_proc = 16
size = 26280000
data = json.dumps((p, v, ers))
procs = []

for i in range(num_proc):
    start = i * size // num_proc
    start = max(start, 1)
    end = (i+1) * size // num_proc
    end = min(end, size)
    print(f"Process {i}: start={start}, end={end}")
    proc = Popen(["sage", "solve2_sub.py", str(i), str(start), str(end)], stdin=PIPE, stdout=sys.stdout, stderr=sys.stderr)
    proc.stdin.write((data + "\n").encode())
    proc.stdin.flush()
    time.sleep(1)
    procs.append(proc)

for proc in procs:
    proc.wait()

ys = []
for i in range(num_proc):
    ys_i = load(f"output/ys_{i}.sobj")
    ys.extend(ys_i)

F = GF(p)
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

f = fast_lagrange(ys)
print(f.degree())
save(f, "output/f.sobj")



